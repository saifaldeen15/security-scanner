```markdown
# Security Scanner Application

The **Security Scanner** is a microservices-based application designed to analyze Python code for security vulnerabilities, code quality issues, and dependency risks. It provides a simple web-based interface for developers to submit their code and receive detailed analysis results, including an overall security score.

---

## Features

- **Static Analysis**: Checks code style, syntax errors, and basic security pitfalls using tools like `pylint`, `pyflakes`, and `bandit`.
- **Dependency Analysis**: Scans imported Python libraries for known vulnerabilities using OSV and PyPI data.
- **AI-Assisted Analysis**: Uses a large language model (Claude) to detect advanced security risks and compliance issues.
- **Persistent Storage**: Stores scan results and code snippets in a MongoDB database with data persistence.
- **Cloud-Native Architecture**: Fully containerized microservices, deployable on Kubernetes.
- **User-Friendly Web Interface**: A web-based frontend for submitting code and viewing results.

---

## Deployment Instructions

### Prerequisites

Before you begin, make sure you have the following tools installed and configured:

1. **Minikube**: A local Kubernetes environment. Install it from [Minikube Installation Guide](https://minikube.sigs.k8s.io/docs/start/).
2. **kubectl**: Kubernetes command-line tool. Install it from [kubectl Installation Guide](https://kubernetes.io/docs/tasks/tools/).
3. **Docker**: To build and push container images. Install it from [Docker Installation Guide](https://docs.docker.com/get-docker/).
4. **Docker Hub Account**: Ensure you have an account and are logged in to push and pull images. Log in using:
   ```bash
   docker login
   ```
---

### Deployment Steps

#### Step 1: Build and Push Docker Containers

For each microservice, follow these steps to build the Docker image and push it to Docker Hub:

1. Navigate to the microservice's directory (e.g., `frontend`, `static-analyzer`, etc.).
   ```bash
   cd <microservice-directory>
   ```
2. Build the Docker image:
   ```bash
   docker build -t <your-dockerhub-username>/<image-name>:<tag> .
   ```
   For example, for the frontend:
   ```bash
   docker build -t your-dockerhub-username/frontend:latest .
   ```
3. Push the image to Docker Hub:
   ```bash
   docker push <your-dockerhub-username>/<image-name>:<tag>
   ```
   For example:
   ```bash
   docker push your-dockerhub-username/frontend:latest
   ```
4. Repeat these steps for each microservice:
   - `frontend`
   - `static-analyzer`
   - `dependency-analyzer`
   - `ai-analyzer`

Ensure that the `image` field in each Kubernetes Deployment file (e.g., `frontend-deployment.yaml`) references your Docker Hub repository and image name.

---

#### Step 2: Start Minikube

Start the Minikube cluster:
```bash
minikube start
```
To confirm that Minikube is running, check the status:
```bash
minikube status
```
---

#### Step 3: Deploy the Application

Apply all Kubernetes resource files in the correct order:

1. Create the namespace:
   ```bash
   kubectl apply -f 0-namespace.yaml
   ```
2. Set up persistent storage for MongoDB:
   ```bash
   kubectl apply -f 1-pv-pvc.yaml
   ```
3. Deploy MongoDB:
   ```bash
   kubectl apply -f 2-mongodb-deployment.yaml
   ```
4. Deploy the Static Analyzer:
   ```bash
   kubectl apply -f 3-static-analyzer-deployment.yaml
   ```
5. Deploy the Dependency Analyzer:
   ```bash
   kubectl apply -f 4-dependency-analyzer-deployment.yaml
   ```
6. Deploy the AI Analyzer:
   ```bash
   kubectl apply -f 5-ai-analyzer-deployment.yaml
   ```
7. Deploy the Frontend:
   ```bash
   kubectl apply -f 6-frontend-deployment.yaml
   ```
   Verify that all resources are running:
   ```bash
   kubectl get pods -n security-scanner
   kubectl get services -n security-scanner
   ```
---

#### Step 4: Access the Application

Expose the frontend service using Minikube:
```bash
minikube service frontend-service -n security-scanner
```
Minikube will open the frontend in your default browser or provide a URL similar to:
```plaintext
http://127.0.0.1:44333
```
If the service does not automatically open in your browser, copy the provided URL and paste it into your browser manually.

---

Follow these instructions to build, deploy, and test the application efficiently.
```