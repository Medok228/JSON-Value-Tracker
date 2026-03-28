"""
Copyright (C) 2026 Medok https://github.com/Medok228

This program is free software: you can use, modify, and redistribute it
under the terms of the GNU General Public License v3 as published by the
Free Software Foundation.

You must retain this copyright notice in all copies or substantial
portions of the software.
"""

"""
JSON Value Tracker - Burp Suite Extension  v1.4
================================================
Fixes:
  - Path bug: root node had path="" causing ".deliveries.0.x" with leading dot
  - Search bug: naive substring "0" matched everywhere; now uses smart boundary search
  - Encoding bug: Jython 2.7 str() chokes on non-ASCII unicode; use unicode() everywhere

Установка:
  Extender -> Options -> Python Environment -> Jython standalone JAR
  Extender -> Extensions -> Add -> Type: Python -> этот файл
"""

from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController

from javax.swing import (
    JPanel, JTabbedPane, JTable, JSplitPane, JScrollPane,
    JTextField, JButton, JLabel, JCheckBox, JOptionPane,
    BorderFactory, ListSelectionModel, Box, SwingUtilities,
    JTextArea, JTree, JSeparator, JRadioButton, ButtonGroup
)
from javax.swing.tree import (
    DefaultMutableTreeNode, DefaultTreeModel, DefaultTreeCellRenderer
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, TreeSelectionListener
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Color, Font, Dimension, FlowLayout, GridLayout
)
from java.awt.event import ActionListener

import json
import re
import threading
from datetime import datetime


# ---------------------------------------------------------------------------
# Jython 2.7 unicode safety helpers
# ---------------------------------------------------------------------------

def _u(obj):
    """
    Safely convert anything to unicode in Jython 2.7.
    Plain str() uses ASCII codec and explodes on cyrillic/CJK.
    """
    if obj is None:
        return u"null"
    try:
        if isinstance(obj, unicode):   # noqa: F821  (unicode built-in in Py2/Jython)
            return obj
    except NameError:
        pass  # Python 3 fallback (shouldn't happen in Jython)
    if isinstance(obj, bool):
        return u"true" if obj else u"false"
    if isinstance(obj, (int, float)):
        return unicode(obj)            # noqa: F821
    if isinstance(obj, str):
        return obj.decode("utf-8", errors="replace")
    try:
        return unicode(obj)            # noqa: F821
    except Exception:
        return repr(obj).decode("ascii", errors="replace")


def _safe_print(msg):
    """Print to Burp console without crashing on non-ASCII."""
    try:
        if not isinstance(msg, str):
            msg = _u(msg).encode("utf-8", errors="replace")
        print(msg)
    except Exception:
        print("[JSON Tracker] (unprintable log message)")


def _json_loads(text):
    """json.loads that accepts both str and unicode in Jython 2.7."""
    try:
        if isinstance(text, unicode):  # noqa: F821
            return json.loads(text)
    except NameError:
        pass
    if isinstance(text, str):
        return json.loads(text.decode("utf-8", errors="replace"))
    return json.loads(text)


def _json_dumps(obj):
    """json.dumps -> always returns unicode, never raises on non-ASCII."""
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
C_BG   = Color(18,  20,  28)
C_CARD = Color(26,  29,  41)
C_ACC  = Color(99,  179, 237)
C_FG   = Color(220, 225, 235)
C_MUTE = Color(120, 125, 145)
C_RED  = Color(245, 101, 101)
C_AMB  = Color(255, 200,  80)
C_PURP = Color(154, 117, 245)
C_GRN  = Color(72,  199, 142)
C_STR  = Color(152, 222, 150)
C_NUM  = Color(255, 188, 100)
C_KEY  = Color(130, 170, 255)
C_NULL = Color(180,  80,  80)
C_HDR  = Color(22,   25,  36)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def build_path(parent_path, key):
    """
    Join parent path + key, skipping empty parent (root level).
    Fixes the leading-dot bug when root path was "".
    """
    key = _u(key)
    if not parent_path:
        return key
    return parent_path + "." + key


def extract_json_path(obj, path):
    """Walk dot-notation path into a parsed JSON object."""
    if not path:
        return obj
    keys = path.strip().split(".")
    cur  = obj
    for k in keys:
        if cur is None:
            return None
        if isinstance(cur, list):
            try:
                cur = cur[int(k)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return None
    return cur


def get_header_value(headers, name):
    target = name.lower()
    for h in headers:
        if ":" in h:
            k, _, v = h.partition(":")
            if k.strip().lower() == target:
                return v.strip()
    return ""


# ---------------------------------------------------------------------------
# Smart value search
# ---------------------------------------------------------------------------

def tracked_value_in_text(tracked_str, original_value, text):
    """
    tracked_str     - _u(original_value), stored as unicode
    original_value  - the actual Python object extracted from JSON
    text            - response body or headers (unicode)

    In Jython 2.7, JSON strings come back as `unicode`, not `str`.
    We must check both `str` and `unicode` for string type detection.
    """
    # Detect if original value is a string type (str or unicode in Jython 2.7)
    is_str_type = isinstance(original_value, basestring)  # noqa: F821 (Py2/Jython)

    if is_str_type:
        # Search as a JSON string literal (with surrounding quotes)
        # e.g. "Москва, Никитский переулок"
        needle = _json_dumps(original_value)
        return needle in text
    elif isinstance(original_value, bool):
        token   = u"true" if original_value else u"false"
        pattern = u'(?<![\"\\w])' + re.escape(token) + u'(?![\"\\w])'
        return bool(re.search(pattern, text))
    elif original_value is None:
        pattern = u'(?<![\"\\w])null(?![\"\\w])'
        return bool(re.search(pattern, text))
    elif isinstance(original_value, (int, float)):
        pattern = u'(?<![\"\\d.\\-])' + re.escape(tracked_str) + u'(?![\\d.])'
        return bool(re.search(pattern, text))
    else:
        return tracked_str in text


# ---------------------------------------------------------------------------
# Tree node
# ---------------------------------------------------------------------------

class JsonNode(DefaultMutableTreeNode):
    def __init__(self, display, path, value, is_leaf_value=False):
        DefaultMutableTreeNode.__init__(self, display)
        self.json_path     = path
        self.json_value    = value
        self.is_leaf_value = is_leaf_value


# ---------------------------------------------------------------------------
# Tree cell renderer
# ---------------------------------------------------------------------------

class JsonTreeRenderer(DefaultTreeCellRenderer):
    def getTreeCellRendererComponent(self, tree, value, sel, expanded,
                                     leaf, row, hasFocus):
        DefaultTreeCellRenderer.getTreeCellRendererComponent(
            self, tree, value, sel, expanded, leaf, row, hasFocus)
        self.setBackground(C_BG)
        self.setBackgroundNonSelectionColor(C_BG)
        self.setBackgroundSelectionColor(Color(40, 80, 130))
        self.setBorderSelectionColor(C_ACC)
        self.setFont(Font("Monospaced", Font.PLAIN, 12))

        if isinstance(value, JsonNode):
            v = value.json_value
            if value.is_leaf_value:
                if v is None:
                    self.setForeground(C_NULL)
                elif isinstance(v, bool):
                    self.setForeground(C_NUM)
                elif isinstance(v, (int, float)):
                    self.setForeground(C_NUM)
                else:
                    self.setForeground(C_STR)
            else:
                self.setForeground(C_KEY)
        else:
            self.setForeground(C_FG)

        self.setOpaque(True)
        return self


# ---------------------------------------------------------------------------
# Build JTree from parsed JSON  (uses build_path -> no leading dot)
# ---------------------------------------------------------------------------

def build_tree(obj, label, path):
    if isinstance(obj, dict):
        node = JsonNode(label + "  { }", path, obj, False)
        for k, v in obj.items():
            node.add(build_tree(v, k, build_path(path, k)))
        return node
    elif isinstance(obj, list):
        node = JsonNode(label + "  [ ]", path, obj, False)
        for i, v in enumerate(obj):
            node.add(build_tree(v, _u(i), build_path(path, i)))
        return node
    else:
        display = _u(label) + u":  " + _json_dumps(obj)
        return JsonNode(display, path, obj, True)


# ---------------------------------------------------------------------------
# Table model
# ---------------------------------------------------------------------------

class ReadOnlyTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)

    def isCellEditable(self, row, col):
        return False


# ---------------------------------------------------------------------------
# Listener wrappers
# ---------------------------------------------------------------------------

class AL(ActionListener):
    def __init__(self, fn):
        self._fn = fn
    def actionPerformed(self, e):
        self._fn(e)


class RowSelL(ListSelectionListener):
    def __init__(self, fn):
        self._fn = fn
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            self._fn()


class TreeSelL(TreeSelectionListener):
    def __init__(self, fn):
        self._fn = fn
    def valueChanged(self, e):
        self._fn(e)


# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JSON Value Tracker")

        self._extract_enabled   = False
        self._extract_url_pat   = ""
        self._extract_json_path = ""
        self._tracked_value     = None   # str
        self._tracked_raw       = None   # original Python object (for smart search)

        self._vf_mode    = "any"
        self._vf_pattern = ""

        self._f_url_inc = ""
        self._f_url_exc = r"\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|eot)(\?.*)?$"
        self._f_status  = ""
        self._f_ctype   = ""
        self._f_body    = True
        self._f_hdrs    = False

        self._hits = []
        self._lock = threading.Lock()

        SwingUtilities.invokeLater(self._build_ui)
        callbacks.registerHttpListener(self)
        _safe_print(u"[JSON Value Tracker] v1.4 loaded")

    # ITab
    def getTabCaption(self):  return "JSON Tracker"
    def getUiComponent(self): return self._main_panel

    # IMessageEditorController
    def getHttpService(self):
        row = self._table.getSelectedRow()
        return self._hits[row]["service"] if 0 <= row < len(self._hits) else None
    def getRequest(self):
        row = self._table.getSelectedRow()
        return self._hits[row]["request"] if 0 <= row < len(self._hits) else None
    def getResponse(self):
        row = self._table.getSelectedRow()
        return self._hits[row]["response"] if 0 <= row < len(self._hits) else None

    # IHttpListener
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if isRequest:
            return
        try:
            self._process(messageInfo)
        except Exception as ex:
            _safe_print(u"[JSON Tracker] error: " + _u(ex))

    # -----------------------------------------------------------------------
    # Core processing
    # -----------------------------------------------------------------------
    def _process(self, info):
        helpers  = self._helpers
        resp     = info.getResponse()
        req      = info.getRequest()
        service  = info.getHttpService()

        resp_info  = helpers.analyzeResponse(resp)
        status     = resp_info.getStatusCode()
        resp_hdrs  = resp_info.getHeaders()
        body_off   = resp_info.getBodyOffset()
        # Decode to unicode explicitly — Jython needs this for json.loads + regex
        body       = bytes(bytearray(resp))[body_off:].decode("utf-8", errors="replace")
        ct         = get_header_value(resp_hdrs, "content-type")

        req_info = helpers.analyzeRequest(service, req)
        url      = _u(req_info.getUrl())

        # ── Phase 1: extract value from source ──────────────────────────
        if self._extract_enabled and self._extract_json_path:
            pat = self._extract_url_pat
            if (not pat) or re.search(pat, url):
                if "json" in ct.lower():
                    try:
                        parsed = _json_loads(body)
                        raw    = extract_json_path(parsed, self._extract_json_path)
                        if raw is not None:
                            candidate = _u(raw)
                            if self._value_matches_filter(candidate):
                                self._tracked_value = candidate
                                self._tracked_raw   = raw
                                disp = candidate[:60]
                                def _upd(d=disp):
                                    self._cfg_status.setText(
                                        u"  [+] Tracking: \u201c" + d + u"\u201d")
                                    self._cfg_status.setForeground(C_GRN)
                                SwingUtilities.invokeLater(_upd)
                    except Exception as ex:
                        _safe_print(u"[JSON Tracker] extract error: " + _u(ex))

        # ── Phase 2: search for tracked value ───────────────────────────
        if not self._tracked_value:
            return

        # URL filters
        if self._f_url_inc:
            try:
                if not re.search(self._f_url_inc, url): return
            except Exception: pass

        if self._f_url_exc:
            try:
                if re.search(self._f_url_exc, url): return
            except Exception: pass

        # Status filter
        if self._f_status:
            allowed = [s.strip() for s in self._f_status.split(",") if s.strip()]
            if _u(status) not in allowed: return

        # Content-Type filter
        if self._f_ctype:
            if self._f_ctype.lower() not in ct.lower(): return

        # Smart search
        found = False
        raw   = self._tracked_raw

        if self._f_body:
            found = tracked_value_in_text(self._tracked_value, raw, body)

        if self._f_hdrs and not found:
            header_blob = u"\n".join([_u(h) for h in resp_hdrs])
            found = tracked_value_in_text(self._tracked_value, raw, header_blob)

        if not found:
            return

        # ── Record hit ──────────────────────────────────────────────────
        ts     = datetime.now().strftime("%H:%M:%S")
        method = _u(req_info.getMethod())

        with self._lock:
            idx = len(self._hits) + 1
            self._hits.append({"request": req, "response": resp, "service": service})

        row_data = [idx, ts, method, url, _u(status), self._tracked_value[:80]]

        def _add(r=row_data):
            self._table_model.addRow(r)
            n = self._table_model.getRowCount()
            self._count_lbl.setText(_u(n) + (u" hit" if n == 1 else u" hits"))

        SwingUtilities.invokeLater(_add)

    def _value_matches_filter(self, val):
        mode = self._vf_mode
        pat  = self._vf_pattern
        if mode == "any" or not pat:
            return True
        if mode == "contains":
            return pat in val
        if mode == "exact":
            return val == pat
        if mode == "regex":
            try:
                return bool(re.search(pat, val))
            except Exception:
                return False
        return True

    # -----------------------------------------------------------------------
    # UI
    # -----------------------------------------------------------------------
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBackground(C_BG)

        self._tabs = JTabbedPane()
        self._tabs.setBackground(C_BG)
        self._tabs.setForeground(C_FG)
        self._tabs.addTab("  JSON Explorer  ", self._build_explorer_tab())
        self._tabs.addTab("  Config         ", self._build_config_tab())
        self._tabs.addTab("  Results        ", self._build_results_tab())

        self._main_panel.add(self._tabs, BorderLayout.CENTER)
        self._cb.addSuiteTab(self)

    # -----------------------------------------------------------------------
    # Tab 1: JSON Explorer
    # -----------------------------------------------------------------------
    def _build_explorer_tab(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(C_BG)
        outer.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

        # Top: paste + parse
        top = JPanel(BorderLayout())
        top.setBackground(C_BG)

        lbl_paste = JLabel("  Paste JSON response body here:")
        lbl_paste.setForeground(C_MUTE)
        lbl_paste.setFont(Font("Monospaced", Font.PLAIN, 11))
        top.add(lbl_paste, BorderLayout.NORTH)

        self._json_input = JTextArea(8, 60)
        self._json_input.setBackground(Color(12, 14, 22))
        self._json_input.setForeground(Color(180, 220, 255))
        self._json_input.setCaretColor(C_ACC)
        self._json_input.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._json_input.setLineWrap(True)
        self._json_input.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(60, 65, 90), 1),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ))
        top.add(JScrollPane(self._json_input), BorderLayout.CENTER)

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 6))
        btn_row.setBackground(C_BG)
        b_parse    = self._btn("  Parse JSON  ", C_ACC)
        b_clear_in = self._btn("  Clear       ", C_MUTE)
        self._parse_err = JLabel("")
        self._parse_err.setForeground(C_RED)
        self._parse_err.setFont(Font("Monospaced", Font.PLAIN, 11))
        btn_row.add(b_parse)
        btn_row.add(Box.createHorizontalStrut(8))
        btn_row.add(b_clear_in)
        btn_row.add(Box.createHorizontalStrut(16))
        btn_row.add(self._parse_err)
        top.add(btn_row, BorderLayout.SOUTH)

        # Bottom: tree + selection panel
        bottom = JPanel(BorderLayout())
        bottom.setBackground(C_BG)

        root_node = DefaultMutableTreeNode("(no JSON parsed)")
        self._tree_model = DefaultTreeModel(root_node)
        self._json_tree  = JTree(self._tree_model)
        self._json_tree.setBackground(C_BG)
        self._json_tree.setForeground(C_FG)
        self._json_tree.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._json_tree.setCellRenderer(JsonTreeRenderer())
        self._json_tree.setRootVisible(True)
        self._json_tree.setRowHeight(20)
        self._json_tree.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        tree_scroll = JScrollPane(self._json_tree)
        tree_scroll.setBorder(BorderFactory.createLineBorder(Color(50, 55, 75), 1))
        tree_scroll.getViewport().setBackground(C_BG)

        sel_panel = self._build_selection_panel()
        sel_panel.setPreferredSize(Dimension(380, 0))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tree_scroll, sel_panel)
        split.setResizeWeight(0.6)
        split.setDividerSize(4)
        bottom.add(split, BorderLayout.CENTER)

        def on_tree_sel(e):
            node = self._json_tree.getLastSelectedPathComponent()
            if node is not None and isinstance(node, JsonNode):
                self._on_node_selected(node)

        self._json_tree.addTreeSelectionListener(TreeSelL(on_tree_sel))

        def on_parse(e):
            text = self._json_input.getText().strip()
            if not text:
                self._parse_err.setText("Empty input")
                return
            try:
                parsed = _json_loads(text)
                root_n = build_tree(parsed, "root", "")
                self._tree_model.setRoot(root_n)
                self._tree_model.reload()
                self._json_tree.expandRow(0)
                self._parse_err.setText("")
            except Exception as ex:
                self._parse_err.setText(("Parse error: " + _u(ex))[:80])

        def on_clear_in(e):
            self._json_input.setText("")
            self._tree_model.setRoot(DefaultMutableTreeNode("(no JSON parsed)"))
            self._tree_model.reload()
            self._parse_err.setText("")

        b_parse.addActionListener(AL(on_parse))
        b_clear_in.addActionListener(AL(on_clear_in))

        vsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bottom)
        vsplit.setResizeWeight(0.30)
        vsplit.setDividerSize(4)
        vsplit.setBackground(C_BG)
        outer.add(vsplit, BorderLayout.CENTER)
        return outer

    def _build_selection_panel(self):
        p = JPanel(GridBagLayout())
        p.setBackground(C_CARD)
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(50, 55, 75), 1),
            BorderFactory.createEmptyBorder(14, 14, 14, 14)
        ))

        gc         = GridBagConstraints()
        gc.fill    = GridBagConstraints.HORIZONTAL
        gc.weightx = 1.0
        gc.gridx   = 0
        gc.insets  = Insets(4, 0, 4, 0)

        gc.gridy = 0
        hdr = JLabel("Selected node")
        hdr.setFont(Font("Monospaced", Font.BOLD, 12))
        hdr.setForeground(C_ACC)
        p.add(hdr, gc)

        gc.gridy = 1; p.add(self._sep(), gc)

        gc.gridy = 2; p.add(self._lbl("JSON Path:"), gc)
        gc.gridy = 3
        self._sel_path = JTextField("")
        self._sel_path.setEditable(False)
        self._sel_path.setBackground(Color(12, 14, 22))
        self._sel_path.setForeground(C_AMB)
        self._sel_path.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._sel_path.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(60, 65, 90), 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ))
        p.add(self._sel_path, gc)

        gc.gridy = 4; p.add(self._lbl("Current value:"), gc)
        gc.gridy = 5
        self._sel_value = JTextField("")
        self._sel_value.setEditable(False)
        self._sel_value.setBackground(Color(12, 14, 22))
        self._sel_value.setForeground(C_STR)
        self._sel_value.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._sel_value.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(60, 65, 90), 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ))
        p.add(self._sel_value, gc)

        gc.gridy = 6; p.add(self._sep(), gc)

        gc.gridy = 7; p.add(self._lbl("Value filter mode:"), gc)

        gc.gridy = 8
        mode_p = JPanel(GridLayout(2, 2, 6, 2))
        mode_p.setBackground(C_CARD)
        self._rb_any      = JRadioButton("Any value", True)
        self._rb_contains = JRadioButton("Contains")
        self._rb_regex    = JRadioButton("Regex")
        self._rb_exact    = JRadioButton("Exact match")
        bg = ButtonGroup()
        for rb in (self._rb_any, self._rb_contains, self._rb_regex, self._rb_exact):
            rb.setBackground(C_CARD)
            rb.setForeground(C_FG)
            rb.setFont(Font("Monospaced", Font.PLAIN, 11))
            bg.add(rb)
            mode_p.add(rb)
        p.add(mode_p, gc)

        gc.gridy = 9
        p.add(self._lbl("Filter pattern  (for Contains / Regex / Exact):"), gc)
        gc.gridy = 10
        self._vf_pat_tf = self._field()
        p.add(self._vf_pat_tf, gc)

        gc.gridy = 11
        hint = JLabel("  Blank = accept any value of this field")
        hint.setForeground(C_MUTE)
        hint.setFont(Font("Monospaced", Font.ITALIC, 10))
        p.add(hint, gc)

        gc.gridy = 12; p.add(self._sep(), gc)

        gc.gridy = 13
        b_apply = self._btn("  Apply  ->  go to Config  ", C_GRN)

        def on_apply(e):
            node_path = self._sel_path.getText().strip()
            if not node_path:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Select a leaf node in the tree first.",
                    "No selection", JOptionPane.WARNING_MESSAGE)
                return
            if self._rb_contains.isSelected(): mode = "contains"
            elif self._rb_regex.isSelected():  mode = "regex"
            elif self._rb_exact.isSelected():  mode = "exact"
            else:                              mode = "any"

            pat = self._vf_pat_tf.getText().strip()
            if not pat and mode != "any":
                pat = self._sel_value.getText().strip()
                self._vf_pat_tf.setText(pat)

            self._vf_mode    = mode
            self._vf_pattern = pat
            self._cfg_path_tf.setText(node_path)
            self._sync_config_radios(mode, pat)
            self._tabs.setSelectedIndex(1)

        b_apply.addActionListener(AL(on_apply))
        p.add(b_apply, gc)

        fill         = GridBagConstraints()
        fill.gridy   = 99
        fill.gridx   = 0
        fill.weighty = 1.0
        fill.fill    = GridBagConstraints.VERTICAL
        p.add(JPanel(), fill)
        return p

    def _on_node_selected(self, node):
        self._sel_path.setText(node.json_path)
        v = node.json_value
        if node.is_leaf_value:
            self._sel_value.setText(_json_dumps(v))
            if not self._vf_pat_tf.getText():
                self._vf_pat_tf.setText(u"" if v is None else _u(v))
        else:
            self._sel_value.setText(u"{ object }" if isinstance(v, dict) else u"[ array ]")
            self._vf_pat_tf.setText(u"")

    # -----------------------------------------------------------------------
    # Tab 2: Config
    # -----------------------------------------------------------------------
    def _build_config_tab(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(C_BG)
        outer.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16))

        wrap = JPanel(GridBagLayout())
        wrap.setBackground(C_BG)

        # Extraction card
        ext = JPanel(GridBagLayout())
        ext.setBackground(C_CARD)
        ec         = GridBagConstraints()
        ec.fill    = GridBagConstraints.HORIZONTAL
        ec.weightx = 1.0
        ec.gridx   = 0
        ec.insets  = Insets(4, 0, 4, 0)

        ec.gridy = 0
        ext.add(self._lbl("Source URL pattern (regex) — blank = any response:"), ec)
        ec.gridy = 1
        self._cfg_src_url = self._field()
        ext.add(self._cfg_src_url, ec)

        ec.gridy = 2
        ext.add(self._lbl("JSON path  (set via Explorer, or type manually):"), ec)
        ec.gridy = 3
        self._cfg_path_tf = self._field()
        ext.add(self._cfg_path_tf, ec)

        ec.gridy = 4; ext.add(self._sep(), ec)
        ec.gridy = 5
        ext.add(self._lbl("Value filter — only track if extracted value matches:"), ec)

        ec.gridy = 6
        vf_p = JPanel(GridLayout(1, 4, 6, 0))
        vf_p.setBackground(C_CARD)
        self._cfg_rb_any      = JRadioButton("Any",      True)
        self._cfg_rb_contains = JRadioButton("Contains")
        self._cfg_rb_regex    = JRadioButton("Regex")
        self._cfg_rb_exact    = JRadioButton("Exact")
        bg2 = ButtonGroup()
        for rb in (self._cfg_rb_any, self._cfg_rb_contains,
                   self._cfg_rb_regex, self._cfg_rb_exact):
            rb.setBackground(C_CARD)
            rb.setForeground(C_FG)
            rb.setFont(Font("Monospaced", Font.PLAIN, 11))
            bg2.add(rb)
            vf_p.add(rb)
        ext.add(vf_p, ec)

        ec.gridy = 7
        self._cfg_vf_pat = self._field()
        ext.add(self._cfg_vf_pat, ec)

        ec.gridy = 8
        hint = JLabel(
            "  e.g. Contains: Bearer  |  Regex: ^[A-Za-z0-9+/=]{20,}$  |  Exact: admin")
        hint.setForeground(C_MUTE)
        hint.setFont(Font("Monospaced", Font.ITALIC, 10))
        ext.add(hint, ec)

        ec.gridy = 9; ext.add(self._sep(), ec)

        ec.gridy = 10
        self._cfg_status = JLabel("  [ ] Not tracking")
        self._cfg_status.setForeground(C_MUTE)
        self._cfg_status.setFont(Font("Monospaced", Font.PLAIN, 11))
        ext.add(self._cfg_status, ec)

        ec.gridy = 11
        brow = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4))
        brow.setBackground(C_CARD)
        b_start = self._btn("  Start Tracking  ", C_ACC)
        b_stop  = self._btn("  Stop / Clear    ", C_RED)

        def on_start(e):
            path = self._cfg_path_tf.getText().strip()
            if not path:
                JOptionPane.showMessageDialog(self._main_panel,
                    "Set a JSON path first (use Explorer or type manually).",
                    "No path", JOptionPane.WARNING_MESSAGE)
                return
            self._extract_url_pat   = self._cfg_src_url.getText().strip()
            self._extract_json_path = path
            self._extract_enabled   = True
            self._tracked_value     = None
            self._tracked_raw       = None
            if self._cfg_rb_contains.isSelected(): self._vf_mode = "contains"
            elif self._cfg_rb_regex.isSelected():  self._vf_mode = "regex"
            elif self._cfg_rb_exact.isSelected():  self._vf_mode = "exact"
            else:                                  self._vf_mode = "any"
            self._vf_pattern = self._cfg_vf_pat.getText().strip()
            self._cfg_status.setText("  [...] Waiting for matching response...")
            self._cfg_status.setForeground(C_AMB)

        def on_stop(e):
            self._extract_enabled = False
            self._tracked_value   = None
            self._tracked_raw     = None
            self._cfg_status.setText("  [ ] Not tracking")
            self._cfg_status.setForeground(C_MUTE)

        b_start.addActionListener(AL(on_start))
        b_stop.addActionListener(AL(on_stop))
        brow.add(b_start)
        brow.add(Box.createHorizontalStrut(8))
        brow.add(b_stop)
        ext.add(brow, ec)

        # Hit filter card
        flt = JPanel(GridBagLayout())
        flt.setBackground(C_CARD)
        fc         = GridBagConstraints()
        fc.fill    = GridBagConstraints.HORIZONTAL
        fc.weightx = 1.0
        fc.gridx   = 0
        fc.insets  = Insets(4, 0, 4, 0)

        fc.gridy = 0; flt.add(self._lbl("URL must match (regex, blank = any):"), fc)
        fc.gridy = 1
        self._f_ui_inc = self._field()
        flt.add(self._f_ui_inc, fc)

        fc.gridy = 2; flt.add(self._lbl("URL must NOT match (regex, blank = disabled):"), fc)
        fc.gridy = 3
        self._f_ui_exc = self._field()
        self._f_ui_exc.setText(self._f_url_exc)
        flt.add(self._f_ui_exc, fc)

        fc.gridy = 4; flt.add(self._lbl("Status codes (comma-sep, blank = any)   e.g. 200,302:"), fc)
        fc.gridy = 5
        self._f_ui_st = self._field()
        flt.add(self._f_ui_st, fc)

        fc.gridy = 6; flt.add(self._lbl("Content-Type must contain (blank = any)   e.g. json:"), fc)
        fc.gridy = 7
        self._f_ui_ct = self._field()
        flt.add(self._f_ui_ct, fc)

        fc.gridy = 8
        chk_p = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4))
        chk_p.setBackground(C_CARD)
        self._chk_body = JCheckBox("Search in body",    self._f_body)
        self._chk_hdrs = JCheckBox("Search in headers", self._f_hdrs)
        for c in (self._chk_body, self._chk_hdrs):
            c.setBackground(C_CARD)
            c.setForeground(C_FG)
            c.setFont(Font("Monospaced", Font.PLAIN, 11))
        chk_p.add(self._chk_body)
        chk_p.add(Box.createHorizontalStrut(20))
        chk_p.add(self._chk_hdrs)
        flt.add(chk_p, fc)

        fc.gridy = 9
        brow2 = JPanel(FlowLayout(FlowLayout.LEFT, 0, 4))
        brow2.setBackground(C_CARD)
        b_save = self._btn("  Save Filters  ", C_PURP)

        def on_save(e):
            self._f_url_inc = self._f_ui_inc.getText().strip()
            self._f_url_exc = self._f_ui_exc.getText().strip()
            self._f_status  = self._f_ui_st.getText().strip()
            self._f_ctype   = self._f_ui_ct.getText().strip()
            self._f_body    = self._chk_body.isSelected()
            self._f_hdrs    = self._chk_hdrs.isSelected()
            JOptionPane.showMessageDialog(self._main_panel,
                "Filters saved!", "OK", JOptionPane.INFORMATION_MESSAGE)

        b_save.addActionListener(AL(on_save))
        brow2.add(b_save)
        flt.add(brow2, fc)

        wc         = GridBagConstraints()
        wc.fill    = GridBagConstraints.HORIZONTAL
        wc.weightx = 1.0
        wc.gridx   = 0
        wc.insets  = Insets(0, 0, 14, 0)

        wc.gridy = 0
        wrap.add(self._card("[ 1 ]  VALUE EXTRACTION  +  VALUE FILTER", ext), wc)
        wc.gridy = 1
        wrap.add(self._card("[ 2 ]  HIT FILTERS  (which responses to search)", flt), wc)

        fill         = GridBagConstraints()
        fill.gridy   = 99; fill.gridx = 0
        fill.weighty = 1.0
        fill.fill    = GridBagConstraints.VERTICAL
        wrap.add(JPanel(), fill)

        outer.add(JScrollPane(wrap), BorderLayout.CENTER)
        return outer

    def _sync_config_radios(self, mode, pat):
        self._cfg_rb_any.setSelected(mode == "any")
        self._cfg_rb_contains.setSelected(mode == "contains")
        self._cfg_rb_regex.setSelected(mode == "regex")
        self._cfg_rb_exact.setSelected(mode == "exact")
        self._cfg_vf_pat.setText(pat)

    # -----------------------------------------------------------------------
    # Tab 3: Results
    # -----------------------------------------------------------------------
    def _build_results_tab(self):
        outer = JPanel(BorderLayout())
        outer.setBackground(C_BG)

        bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        bar.setBackground(C_HDR)
        bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(45, 50, 70)))
        self._count_lbl = JLabel("0 hits")
        self._count_lbl.setForeground(C_ACC)
        self._count_lbl.setFont(Font("Monospaced", Font.BOLD, 12))
        b_clr = self._btn("  Clear Results  ", C_RED)
        bar.add(self._count_lbl)
        bar.add(Box.createHorizontalStrut(12))
        bar.add(b_clr)
        outer.add(bar, BorderLayout.NORTH)

        def on_clear(e):
            with self._lock:
                self._hits = []
            self._table_model.setRowCount(0)
            self._count_lbl.setText("0 hits")

        b_clr.addActionListener(AL(on_clear))

        cols = ["#", "Time", "Method", "URL", "Status", "Matched Value"]
        self._table_model = ReadOnlyTableModel(cols, 0)
        self._table       = JTable(self._table_model)
        self._table.setBackground(Color(14, 16, 24))
        self._table.setForeground(C_FG)
        self._table.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._table.setGridColor(Color(35, 38, 55))
        self._table.setSelectionBackground(Color(40, 80, 130))
        self._table.setSelectionForeground(Color(255, 255, 255))
        self._table.setRowHeight(22)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        th = self._table.getTableHeader()
        th.setBackground(C_HDR)
        th.setForeground(C_ACC)
        th.setFont(Font("Monospaced", Font.BOLD, 11))

        for i, w in enumerate([40, 90, 65, 420, 60, 220]):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self._table.getSelectionModel().addListSelectionListener(RowSelL(self._on_row_select))

        self._req_ed  = self._cb.createMessageEditor(self, False)
        self._resp_ed = self._cb.createMessageEditor(self, False)

        req_p  = self._labeled("REQUEST",  self._req_ed.getComponent())
        resp_p = self._labeled("RESPONSE", self._resp_ed.getComponent())

        hsplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_p, resp_p)
        hsplit.setResizeWeight(0.45)
        hsplit.setDividerSize(4)

        vsplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self._table), hsplit)
        vsplit.setResizeWeight(0.35)
        vsplit.setDividerSize(4)

        outer.add(vsplit, BorderLayout.CENTER)
        return outer

    def _on_row_select(self):
        row = self._table.getSelectedRow()
        if 0 <= row < len(self._hits):
            h = self._hits[row]
            self._req_ed.setMessage(h["request"],  True)
            self._resp_ed.setMessage(h["response"], False)

    # -----------------------------------------------------------------------
    # Widget helpers
    # -----------------------------------------------------------------------
    def _lbl(self, text):
        l = JLabel(text)
        l.setForeground(C_FG)
        l.setFont(Font("Monospaced", Font.PLAIN, 11))
        return l

    def _field(self):
        tf = JTextField()
        tf.setBackground(Color(12, 14, 22))
        tf.setForeground(Color(180, 220, 255))
        tf.setCaretColor(C_ACC)
        tf.setFont(Font("Monospaced", Font.PLAIN, 12))
        tf.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(60, 65, 90), 1),
            BorderFactory.createEmptyBorder(5, 8, 5, 8)
        ))
        return tf

    def _btn(self, text, bg):
        b = JButton(text)
        b.setBackground(bg)
        b.setForeground(Color(12, 14, 22))
        b.setFont(Font("Monospaced", Font.BOLD, 11))
        b.setFocusPainted(False)
        b.setOpaque(True)
        b.setBorder(BorderFactory.createEmptyBorder(6, 14, 6, 14))
        return b

    def _sep(self):
        s = JSeparator()
        s.setForeground(Color(50, 55, 75))
        s.setBackground(C_CARD)
        return s

    def _card(self, title, content):
        p = JPanel(BorderLayout())
        p.setBackground(C_CARD)
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(50, 55, 75), 1),
            BorderFactory.createEmptyBorder(14, 16, 14, 16)
        ))
        h = JLabel(title)
        h.setFont(Font("Monospaced", Font.BOLD, 12))
        h.setForeground(C_ACC)
        h.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0))
        p.add(h, BorderLayout.NORTH)
        p.add(content, BorderLayout.CENTER)
        return p

    def _labeled(self, title, component):
        p = JPanel(BorderLayout())
        p.setBackground(C_CARD)
        h = JLabel("  " + title)
        h.setForeground(C_ACC)
        h.setFont(Font("Monospaced", Font.BOLD, 11))
        h.setOpaque(True)
        h.setBackground(C_HDR)
        h.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8))
        p.add(h, BorderLayout.NORTH)
        p.add(component, BorderLayout.CENTER)
        return p
