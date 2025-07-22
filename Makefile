.PHONY: lint test vendor clean build docker-build docker-push deploy k8s-deploy k8s-delete k8s-redeploy test-curl

export GO111MODULE=on
DOCKER_IMAGE=zalbiraw/ociauth
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

docker-build:
	docker build --platform linux/amd64 -t $(DOCKER_IMAGE):$(TAG) .
	docker tag $(DOCKER_IMAGE):$(TAG) $(DOCKER_IMAGE):latest

docker-push: docker-build
	docker push $(DOCKER_IMAGE):$(TAG)
	docker push $(DOCKER_IMAGE):latest

deploy: docker-push k8s-deploy

k8s-deploy:
	kubectl apply -f k8s/

k8s-delete:
	kubectl delete -f k8s/ --ignore-not-found=true

k8s-redeploy: k8s-delete k8s-deploy

refresh: docker-push
	kubectl rollout restart deployment/ociauth -n $(NAMESPACE)
	kubectl rollout status deployment/ociauth -n $(NAMESPACE)

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
	curl -X GET "http://localhost:8080/20231130/models?compartmentId=$(OCI_COMPARTMENT_ID)&capability=CHAT" \
		-H "Content-Type: application/json" \
		-v && \
	echo "" && \
	echo "Stopping port-forward..." && \
	kill $$PF_PID 2>/dev/null || true