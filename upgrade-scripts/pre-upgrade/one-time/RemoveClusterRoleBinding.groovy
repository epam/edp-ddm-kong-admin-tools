void call() {
    sh "echo Removing existing ClusterRoleBinding..."

    sh "oc delete clusterrolebinding kong-admin-tools-cluster-role || true"
}

return this;
