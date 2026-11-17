.PHONY: up down build ps logs test validate k8s-validate k8s-apply k8s-delete k8s-status k8s-scale-scoring

up:
	docker compose up -d --build

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

k8s-validate:
	kubectl kustomize k8s/ > /dev/null

k8s-apply:
	kubectl apply -k k8s/

k8s-delete:
	kubectl delete -k k8s/

k8s-status:
	kubectl get pods,svc,deployments,pvc -n antifraud

k8s-scale-scoring:
	kubectl scale deployment service-scoring -n antifraud --replicas=3
