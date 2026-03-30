import json

SRC_FILE = "audit.log"
DST_FILE = "audit-extract.json"

# Список для накопления подозрительных событий
alerts = []

def is_privileged_pod(event_data):
    """
    Проверка: есть ли в поде контейнеры с privileged=true
    """
    try:
        containers = event_data["requestObject"]["spec"]["containers"]
        return any(
            container.get("securityContext", {}).get("privileged") is True
            for container in containers
        )
    except Exception:
        return False


def process_event(evt):
    """
    Анализ одного события audit-лога
    Возвращает True, если событие считается подозрительным
    """
    obj = evt.get("objectRef", {})
    uri = evt.get("requestURI", "")

    # 1. Доступ к секретам
    if obj.get("resource") == "secrets":
        return True

    # 2. Выполнение команды в контейнере (kubectl exec)
    if obj.get("subresource") == "exec":
        return True

    # 3. Привилегированный pod
    if is_privileged_pod(evt):
        return True

    # 4. Изменения RBAC (rolebinding / clusterrolebinding)
    if obj.get("resource") in ("rolebindings", "clusterrolebindings"):
        return True

    # 5. Операции с audit policy
    if "audit-policy" in uri:
        return True

    return False


with open(SRC_FILE, "r") as src:
    for raw_line in src:
        try:
            parsed = json.loads(raw_line)
        except Exception:
            # Пропускаем битые строки
            continue

        if process_event(parsed):
            alerts.append(parsed)


# Сохраняем результат в файл
with open(DST_FILE, "w") as dst:
    json.dump(alerts, dst, indent=2)


print(f"Найдено подозрительных событий: {len(alerts)}")