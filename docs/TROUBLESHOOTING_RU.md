# Устранение неисправностей

## Вкладка Procmon Events не появляется

Вкладка отображается только если существует непустой файл:

```bash
cd /opt/CAPEv2
ID=<task-id>
ls -lh "storage/analyses/$ID/aux/procmon.xml"
```

Если файла нет, сначала разберитесь со сбором и загрузкой Procmon. WebUI не может показать данные, которые не попали на хост.

## Analyzer сообщает, что XML загружен, но файла на хосте нет

Проверьте лимиты ResultServer и его логи. Большие Procmon XML могут превышать лимит загрузки.

```bash
cd /opt/CAPEv2
grep -nE 'upload_max_size|analysis_size_limit' conf/cuckoo.conf
journalctl -u cape --no-pager | grep -iE 'upload|max|procmon'
```

## Вкладка появилась, но возвращает ошибку

Проверьте лог WebUI:

```bash
journalctl -u cape-web -n 200 --no-pager
```

Также выполните:

```bash
cd /opt/CAPEv2
poetry run python3 -m py_compile web/analysis/procmon_view.py web/analysis/views.py web/analysis/urls.py
poetry run python3 web/manage.py check
```

## Первое открытие работает медленно

При первом запросе создаётся временный SQLite-индекс:

`/tmp/cape-procmon-ui`

Для большого XML это может занять несколько секунд. Следующие поиски и страницы используют готовый кэш. Кэш автоматически считается устаревшим при изменении размера или `mtime` исходного XML.

## Очистка производного кэша

```bash
rm -rf /tmp/cape-procmon-ui
```

При следующем открытии страницы индекс будет создан заново.

## Откат WebUI-расширения

Из каталога репозитория:

```bash
python3 uninstall.py --root /opt/CAPEv2
sudo systemctl restart cape-web
```

Installer сохраняет исходные файлы в `/opt/CAPEv2/.procmon-ui-backups/` и автоматически выполняет rollback, если проверки установки завершаются ошибкой.
