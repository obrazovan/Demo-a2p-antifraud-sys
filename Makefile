.PHONY: up down build ps logs test validate

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

ps:
	docker compose ps

logs:
	docker compose logs -f

validate:
	docker compose config -q

test:
	python -m pytest -v
