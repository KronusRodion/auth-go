# Auth Service

Сервис аутентификации на Go с использованием JWT и refresh-токенов, защищенный от повторного использования токенов и проверкой User-Agent.

## Технологии

- **Go** - основной язык программирования
- **PostgreSQL** - хранение refresh-токенов
- **Docker** - контейнеризация приложения
- **Swagger** - документация API

## Запуск проекта

1. Убедитесь, что установлены Docker и Docker Compose.
2. Склонируйте репозиторий:
   ```bash
   git clone https://github.com/your-repo/auth-go.git 
   cd auth-go

3. Запуск проекта командой
  - docker-compose -f docker-compose.yml up -d

5. Проверить работу АПИ можно будет на http://localhost:8080
