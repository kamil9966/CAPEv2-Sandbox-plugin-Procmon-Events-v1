# Архитектура

```text
Procmon в гостевой Windows
       |
       | экспорт PML -> XML
       v
CAPE ResultServer
       |
       v
storage/analyses/<task>/aux/procmon.xml
       |
       +--> модуль обработки Procmon в CAPE (для этого UI необязателен)
       |
       +--> Procmon Investigation UI
              |
              +--> потоковый XML-парсер
              +--> корреляция processlist по ProcessIndex
              +--> временный SQLite-индекс в /tmp/cape-procmon-ui
              +--> вкладка отчёта с пагинацией
              +--> карточка события
              +--> рекурсивный / field-aware поиск
```

Backend использует `xml.etree.ElementTree.iterparse()`, чтобы не загружать XML размером в сотни мегабайт целиком в память. Метаданные процессов из Procmon `<processlist>` сохраняются в компактном словаре и связываются с событиями по `ProcessIndex`.

SQLite-кэш содержит только производные данные. Он привязан к пути исходного XML, создаётся с блокировкой для worker-процессов и перестраивается при изменении исходного файла. Миграция схем CAPE SQL/Mongo/Elastic не требуется.

Django endpoint сохраняет стандартную защиту видимости задач CAPE и использует безопасные GET-запросы. Шаблоны используют стандартное Django-экранирование данных событий.
