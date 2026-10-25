pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 40, unit: 'MINUTES')
    }

    triggers {
        // Poll GitHub about every 2 minutes, so Jenkins needs no inbound webhook.
        pollSCM('H/2 * * * *')
    }

    environment {
        DOCKERHUB_USER = 'dhruvgupta0311'   // <-- CHANGE THIS
        BACKEND_IMAGE  = "${DOCKERHUB_USER}/aegis-backend"
        GATEWAY_IMAGE  = "${DOCKERHUB_USER}/aegis-gateway"
        IMAGE_TAG      = "${BUILD_NUMBER}"
        NAMESPACE      = 'aegis'
        // Secret-file credential: Jenkins writes it to a temp file and sets KUBECONFIG to that path.
        KUBECONFIG     = credentials('minikube-kubeconfig')
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh 'git log -1 --oneline'
            }
        }

        stage('Build and Test') {
            environment {
                // CI-only dummy values so the app config loads without a real .env.
                JWT_SECRET_KEY = 'ci-only-dummy-secret-key-at-least-32-characters'
                DATABASE_URL   = 'mysql+pymysql://ci:ci@localhost:3306/ci'
                GEMINI_API_KEY = 'placeholder'
            }
            steps {
                // Tests run inside a throwaway python:3.12 container, so Jenkins itself needs no Python.
                // test_auth.py needs a live MySQL server, so it is excluded in CI.
                sh '''
                    CID=$(docker create -w /app \
                        -e JWT_SECRET_KEY -e DATABASE_URL -e GEMINI_API_KEY \
                        python:3.12-slim \
                        sh -c "pip install --quiet -r backend/requirements.txt pytest httpx pytest-asyncio && pytest --ignore=backend/tests/integration --ignore=backend/tests/test_auth.py -q")
                    docker cp . "$CID":/app
                    docker start -a "$CID" || true
                    RC=$(docker inspect -f '{{.State.ExitCode}}' "$CID")
                    docker rm -f "$CID" > /dev/null
                    exit "$RC"
                '''
            }
        }

        stage('Docker Build') {
            steps {
                sh '''
                    docker build -f backend/Dockerfile -t $BACKEND_IMAGE:$IMAGE_TAG .
                    docker build -f gateway/Dockerfile.k8s -t $GATEWAY_IMAGE:$IMAGE_TAG .
                '''
            }
        }

        stage('Push Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds',
                                                  usernameVariable: 'DH_USER',
                                                  passwordVariable: 'DH_TOKEN')]) {
                    sh '''
                        echo "$DH_TOKEN" | docker login -u "$DH_USER" --password-stdin
                        docker push $BACKEND_IMAGE:$IMAGE_TAG
                        docker push $GATEWAY_IMAGE:$IMAGE_TAG
                    '''
                }
            }
        }

        stage('Minikube Deployment') {
            steps {
                withCredentials([
                    string(credentialsId: 'aegis-jwt-secret',       variable: 'JWT_SECRET'),
                    string(credentialsId: 'aegis-db-password',      variable: 'DB_PASS'),
                    string(credentialsId: 'aegis-db-root-password', variable: 'DB_ROOT')
                ]) {
                    sh '''
                        kubectl get nodes
                        kubectl apply -f k8s/00-namespace.yaml

                        # The Secret is built from Jenkins credentials and is never stored in Git.
                        kubectl -n $NAMESPACE create secret generic aegis-secrets \
                          --from-literal=JWT_SECRET_KEY="$JWT_SECRET" \
                          --from-literal=JWT_ACCESS_TOKEN_EXPIRE_MINUTES=480 \
                          --from-literal=GEMINI_API_KEY=placeholder \
                          --from-literal=MYSQL_ROOT_PASSWORD="$DB_ROOT" \
                          --from-literal=MYSQL_DATABASE=aegis \
                          --from-literal=MYSQL_USER=aegis_user \
                          --from-literal=MYSQL_PASSWORD="$DB_PASS" \
                          --from-literal=DATABASE_URL="mysql+pymysql://aegis_user:${DB_PASS}@aegis-mysql:3306/aegis" \
                          --dry-run=client -o yaml | kubectl apply -f -

                        kubectl apply -f k8s/mysql.yaml
                        sed "s|__BACKEND_IMAGE__|${BACKEND_IMAGE}:${IMAGE_TAG}|g" k8s/backend.yaml | kubectl apply -f -
                        sed "s|__GATEWAY_IMAGE__|${GATEWAY_IMAGE}:${IMAGE_TAG}|g" k8s/gateway.yaml | kubectl apply -f -

                        kubectl -n $NAMESPACE rollout status deployment/aegis-mysql --timeout=240s
                        kubectl -n $NAMESPACE rollout status deployment/backend --timeout=240s
                        kubectl -n $NAMESPACE rollout status deployment/gateway --timeout=240s
                    '''
                }
            }
        }

        stage('Verification') {
            steps {
                sh '''
                    kubectl -n $NAMESPACE get pods,deploy,svc -o wide

                    NODEPORT=$(kubectl -n $NAMESPACE get svc gateway -o jsonpath='{.spec.ports[0].nodePort}')
                    # Node IP from the cluster itself. Jenkins must be attached to the "minikube" Docker network.
                    NODEIP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
                    URL="http://${NODEIP}:${NODEPORT}"

                    curl --retry 10 --retry-delay 3 --retry-connrefused -fsS "$URL/health"
                    echo
                    curl -fsS -o /dev/null "$URL/"

                    # Without a token the API must answer 401/403. A 502 would mean the backend is down.
                    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$URL/api/auth/me")
                    echo "API via gateway returned HTTP $CODE (401/403 expected without a token)"
                    [ "$CODE" = "401" ] || [ "$CODE" = "403" ]

                    echo "Deployed image tag: $IMAGE_TAG"
                    echo "App URL on the Docker network: $URL"
                '''
            }
        }
    }

    post {
        failure {
            sh '''
                kubectl -n $NAMESPACE get pods -o wide || true
                kubectl -n $NAMESPACE describe pods | tail -60 || true
            '''
        }
        always {
            sh 'docker logout || true'
            sh 'docker image prune -f || true'
        }
    }
}
