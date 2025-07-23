.PHONY: lint test vendor clean build build-debug docker-build docker-build-debug docker-push docker-push-debug deploy deploy-debug k8s-deploy k8s-deploy-debug k8s-delete k8s-delete-debug k8s-redeploy k8s-redeploy-debug refresh refresh-debug test-curl test-debug dev-cycle dev-cycle-debug

export GO111MODULE=on
DOCKER_IMAGE=zalbiraw/ociauth
DEBUG_IMAGE=zalbiraw/ociauth-debug
TAG=$(shell git rev-parse --short HEAD)
NAMESPACE=default

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor

build:
	go build -o bin/server ./cmd/server

build-debug:
	go build -o bin/debug-proxy ./cmd/debug-proxy

docker-build:
	docker build --platform linux/amd64 --target server -t $(DOCKER_IMAGE):$(TAG) .
	docker tag $(DOCKER_IMAGE):$(TAG) $(DOCKER_IMAGE):latest

docker-build-debug:
	docker build --platform linux/amd64 --target debug-proxy -t $(DEBUG_IMAGE):$(TAG) .
	docker tag $(DEBUG_IMAGE):$(TAG) $(DEBUG_IMAGE):latest

docker-push: docker-build
	docker push $(DOCKER_IMAGE):$(TAG)
	docker push $(DOCKER_IMAGE):latest

docker-push-debug: docker-build-debug
	docker push $(DEBUG_IMAGE):$(TAG)
	docker push $(DEBUG_IMAGE):latest

deploy: docker-push k8s-deploy

deploy-debug: docker-push-debug k8s-deploy-debug

k8s-deploy:
	kubectl apply -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/configmap.yaml -f k8s/ingress.yaml

k8s-deploy-debug:
	kubectl apply -f k8s/debug-proxy-deployment.yaml -f k8s/debug-proxy-service.yaml

k8s-delete:
	kubectl delete -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/configmap.yaml -f k8s/ingress.yaml --ignore-not-found=true

k8s-delete-debug:
	kubectl delete -f k8s/debug-proxy-deployment.yaml -f k8s/debug-proxy-service.yaml --ignore-not-found=true

k8s-redeploy: k8s-delete k8s-deploy

k8s-redeploy-debug: k8s-delete-debug k8s-deploy-debug

refresh: docker-push
	kubectl rollout restart deployment/ociauth -n $(NAMESPACE)
	kubectl rollout status deployment/ociauth -n $(NAMESPACE)

refresh-debug: docker-push-debug
	kubectl rollout restart deployment/debug-proxy -n $(NAMESPACE)
	kubectl rollout status deployment/debug-proxy -n $(NAMESPACE)

test-curl:
	@echo "Testing OCI Auth service via port-forward..."
	@echo "Getting compartment ID..."
	$(eval OCI_COMPARTMENT_ID := $(shell oci iam compartment list --all --query 'data[0]."compartment-id"' --raw-output))
	@echo "Using compartment ID: $(OCI_COMPARTMENT_ID)"
	@echo "Starting port-forward in background..."
	@kubectl port-forward service/ociauth-service 8080:80 > /dev/null 2>&1 & \
	PF_PID=$$! && \
	sleep 3 && \
	echo "Testing service endpoint..." && \
	curl "http://localhost:8080/20231130/models?compartmentId=$(OCI_COMPARTMENT_ID)&capability=CHAT" \
		-H "Content-Type: application/json" \
		-v && \
	echo "" && \
	echo "Stopping port-forward..." && \
	kill $$PF_PID 2>/dev/null || true

test-debug:
	@echo "Testing Debug Proxy service via port-forward..."
	@echo "Starting port-forward in background..."
	@kubectl port-forward service/debug-proxy-service 8081:80 > /dev/null 2>&1 & \
	PF_PID=$$! && \
	sleep 3 && \
	echo "Testing debug proxy endpoint..." && \
	curl "http://localhost:8081/anything?test=debug&proxy=working" \
		-H "Content-Type: application/json" \
		-H "X-Test-Header: debug-proxy-test" \
		-d '{"message": "test debug proxy"}' \
		-v && \
	echo "" && \
	echo "Stopping port-forward..." && \
	kill $$PF_PID 2>/dev/null || true

dev-cycle: lint test build docker-push refresh
	@echo "Development cycle complete for main service"

dev-cycle-debug: lint test build-debug docker-push-debug refresh-debug
	@echo "Development cycle complete for debug proxy"