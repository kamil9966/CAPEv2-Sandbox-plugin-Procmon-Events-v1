# Синтаксис поиска

Верхняя строка поиска выполняет AND-поиск по индексированным событиям Procmon и связанным метаданным процесса.

Примеры:

```text
powershell WriteFile
"ExecutionPolicy Bypass"
cmd:"ExecutionPolicy Bypass"
operation:RegSetValue
path:\AppData\Local\Temp
parent:EXCEL.EXE
pid:4408
integrity:High
ProcessIndex:105
CustomParameter:SecretPhrase
```

Поддерживаемые алиасы:

- `process:` / `proc:`
- `pid:`
- `operation:` / `op:`
- `path:`
- `result:`
- `detail:`
- `cmd:` / `command:` / `commandline:`
- `parent:` / `parent_process:`
- `parent_pid:` / `ppid:`
- `user:` / `owner:`
- `integrity:`
- `tid:`
- `duration:`
- `image:` / `image_path:`
- `class:` / `event_class:`
- `category:`
- `process_index:`

Неизвестные имена полей не отбрасываются. Они ищутся в развёрнутом raw XML как `FieldName:value`, поэтому можно искать параметры Procmon, которые не вынесены в отдельные колонки таблицы.

Текст в кавычках считается одной фразой. Несколько условий объединяются через AND. Поиск регистронезависимый.
