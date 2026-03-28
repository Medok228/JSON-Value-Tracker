# JSON Value Tracker (Burp Suite Extension)

JSON Value Tracker — расширение для Burp Suite, которое позволяет извлекать значения из JSON и автоматически отслеживать их в трафике.

---

## 🚀 Возможности / Преимущества

- 🔍 Поиск значений из JSON по path (например: `items.0.location.address`)
- 🎯 Точечный поиск по конкретному path (даже если в JSON есть такие же ключи выше/ниже по структуре)
- 🔁 Автоматический трекинг значений в других запросах
- 🧠 Smart search (без ложных совпадений)
- 🎛 Гибкие фильтры (URL, статус, content-type)
- 🌍 Поддержка кириллицы (Unicode-safe)
- 📊 Удобный UI с таблицей и request/response

---

## ⚙️ Установка

1. Установи Jython standalone JAR (2.7.x)
2. Burp → Extender → Options → Python Environment
3. Добавь расширение (Type: Python)

---

## 🧪 Использование

1. Вставь JSON в JSON Explorer  
2. Найди нужное значение → получи JSON path  
3. Перейди в Config  
4. Нажми Start Tracking  
5. Анализируй результаты  

---

## 🔬 Пример (обезличенный)

Структура:

```
items → 0 → location → address
```

Path:
```
items.0.location.address
```

Фильтр:
```
Contains: City
```

Что важно:

Если в JSON есть несколько полей `address` в разных местах, расширение:
- не будет искать по всему JSON
- а возьмёт значение **строго по указанному path**



---


