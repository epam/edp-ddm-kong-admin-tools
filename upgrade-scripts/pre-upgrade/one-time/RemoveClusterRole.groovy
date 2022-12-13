void call() {
    sh "echo Removing existing ClusterRoler..."

    sh "oc delete clusterrole kong-admin-tools-cluster-role || true"
}

return this;
