#!/bin/bash

# Test script to check which OCI models work with chat completions
BASE_URL="http://openai.traefik.cloud"
HOST_HEADER="openai.traefik.cloud"

echo "=== Testing OCI Models via Traefik ==="
echo "Getting list of available models..."

# Get the list of models
models_response=$(curl -s -H "Host: $HOST_HEADER" "$BASE_URL/v1/models")

if [ $? -ne 0 ]; then
    echo "❌ Failed to get models list"
    exit 1
fi

echo "Models response:"
echo "$models_response" | jq . 2>/dev/null || echo "$models_response"
echo ""

# Extract model IDs (assuming JSON response with data array containing objects with id field)
model_ids=$(echo "$models_response" | jq -r '.data[]?.id' 2>/dev/null)

if [ -z "$model_ids" ]; then
    echo "❌ Could not extract model IDs from response"
    echo "Please check the models endpoint response format"
    exit 1
fi

echo "Found models:"
echo "$model_ids"
echo ""

# Arrays to store results
working_models=()
failed_models=()

# Test each model
for model in $model_ids; do
    echo "🧪 Testing model: $model"
    
    # Make chat completion request
    response=$(curl -i -s -X POST "$BASE_URL/v1/chat/completions" \
        -H "Host: $HOST_HEADER" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"$model\",
            \"messages\": [
                {
                    \"role\": \"user\",
                    \"content\": \"Hello, how are you?\"
                }
            ],
            \"max_tokens\": 150,
            \"temperature\": 0.7
        }")
    
    # Check if request was successful (look for HTTP 200 and proper JSON response)
    if echo "$response" | grep -q "HTTP/.*200" && echo "$response" | grep -q '"choices"'; then
        echo "✅ $model - WORKING"
        working_models+=("$model")
        # Show a snippet of the response
        echo "   Response snippet:"
        echo "$response" | tail -n +10 | jq -r '.choices[0].message.content' 2>/dev/null | head -c 100
        echo "..."
    else
        echo "❌ $model - FAILED"
        failed_models+=("$model")
        # Show error details
        echo "   Error details:"
        echo "$response" | tail -n 5
    fi
    
    echo ""
    sleep 1  # Be nice to the API
done

echo "=== RESULTS SUMMARY ==="
echo ""

if [ ${#working_models[@]} -gt 0 ]; then
    echo "✅ WORKING MODELS (${#working_models[@]}):"
    for model in "${working_models[@]}"; do
        echo "  - $model"
    done
else
    echo "❌ No working models found"
fi

echo ""

if [ ${#failed_models[@]} -gt 0 ]; then
    echo "❌ FAILED MODELS (${#failed_models[@]}):"
    for model in "${failed_models[@]}"; do
        echo "  - $model"
    done
else
    echo "✅ All models working!"
fi

echo ""
echo "=== Test completed ==="