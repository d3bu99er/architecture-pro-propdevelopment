### Проверка пунктов 1–4 выполняется следующим образом:

В каталоге [verify](verify) находятся два скрипта, предназначенные для проверки корректности манифестов,
расположенных в директориях [insecure-manifests](insecure-manifests) и [secure-manifests](secure-manifests).

Порядок запуска:

```shell
chmod +x verify/verify-admission.sh verify/validate-security.sh \
./verify/verify-admission.sh
./verify/validate-security.sh
```

### Проверка пункта 5 выполняется следующим образом:

1. Установка Gatekeeper:
   ```shell
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.22.0/deploy/gatekeeper.yaml
   ```

2. Применение конфигураций Gatekeeper:
   ```shell
   kubectl apply -f gatekeeper/constraint-templates
   kubectl apply -f gatekeeper/constraints
   ```

3. Создание пространства имён и проверка политик:
   ```shell
   kubectl create namespace gatekeeper-test
   kubectl apply -f gatekeeper/verify/bad-pod.yaml
   kubectl apply -f gatekeeper/verify/safe-pod.yaml
   ```

   Ожидаемый результат:
   - При применении `bad-pod.yaml` ресурс не должен создаться, так как нарушает заданные политики.
   - При применении `safe-pod.yaml` ресурс должен успешно создаться, поскольку соответствует установленным правилам.
