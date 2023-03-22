void call() {
    sh "echo Removing existing ClusterRoleBinding..."

    sh "oc delete clusterrolebinding kong-admin-tools-kong-admin-tools-$NAMESPACE || true"
}

return this;
