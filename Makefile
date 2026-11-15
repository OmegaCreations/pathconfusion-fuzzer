.PHONY: up down logs ps rebuild

up:
	docker compose up -d --build

down:
	docker compose down -v

logs:
	docker compose logs -f

ps:
	docker compose ps

rebuild:
	docker compose build --no-cache
