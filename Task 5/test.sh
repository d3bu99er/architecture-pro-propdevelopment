#!/bin/bash

# Тест 1: front-end -> back-end (ДОЛЖЕН работать)
echo "=== Тест 1: front-end -> back-end (должен работать) ==="
kubectl exec front-end-app -- curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" back-end-api-app:80

# Тест 2: front-end -> admin-back-end (НЕ должен работать)
echo "=== Тест 2: front-end -> admin-back-end (НЕ должен работать) ==="
kubectl exec front-end-app -- timeout 3 curl -v admin-back-end-api-app:80 2>&1 | grep -E "(Connection refused|timeout|Failed to connect)"

# Тест 3: admin-front-end -> admin-back-end (ДОЛЖЕН работать)
echo "=== Тест 3: admin-front-end -> admin-back-end (должен работать) ==="
kubectl exec admin-front-end-app -- curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" admin-back-end-api-app:80

# Тест 4: admin-front-end -> back-end (НЕ должен работать)
echo "=== Тест 4: admin-front-end -> back-end (НЕ должен работать) ==="
kubectl exec admin-front-end-app -- timeout 3 curl -v back-end-api-app:80 2>&1 | grep -E "(Connection refused|timeout|Failed to connect)"