package com.epam.edp.stages.impl.ci.impl.builddockerfileimage

import com.epam.edp.stages.impl.ci.ProjectType
import com.epam.edp.stages.impl.ci.Stage
import com.epam.edp.stages.impl.ci.impl.codebaseiamgestream.CodebaseImageStreams

@Stage(name = "build-image-from-dockerfile", buildTool = ["docker"], type = [ProjectType.APPLICATION])
class BuildDockerfileImageDocker {
    Script script


    void run(context) {
        script.sh "chmod -R +x ${context.workDir}"

        script.dir("${context.workDir}/kong-build-tools") {
            script.sh """sudo /bin/bash -c 'export RESTY_IMAGE_BASE=alpine;
                      export RESTY_IMAGE_TAG=latest;
                      export PACKAGE_TYPE=apk;
                      make package-kong'"""
        }

        if (!script.fileExists("${context.workDir}/Dockerfile")) {
            script.error "[JENKINS][ERROR] There is no Dockerfile in the root directory of the project ${context.codebase.name}. "
        }

        script.openshift.withCluster() {
            script.openshift.withProject() {
                def dockerRegistryHost = context.platform.getJsonPathValue("edpcomponent", "docker-registry", ".spec.url")
                script.println "[DEBUG] Docker registry host: ${dockerRegistryHost}"

                if (!dockerRegistryHost)
                    script.error("[JENKINS][ERROR] Couldn't get docker registry server")

                def outputImagestreamName = "${context.codebase.name}-${context.git.branch.replaceAll("[^\\p{L}\\p{Nd}]+", "-")}"
                script.println "[DEBUG] outputImagestreamName: ${outputImagestreamName}"
                def imageRepository = "${dockerRegistryHost}/${context.job.ciProject}/${outputImagestreamName}"
                script.println "[DEBUG] imageUrl: ${imageRepository}"
                def imageUrl = "${imageRepository}:${context.codebase.isTag}"
                script.println "[DEBUG] imageUrl: ${imageUrl}"

                script.dir("${context.workDir}") {
                    script.withCredentials([script.usernamePassword(credentialsId: "docker-registry-credentials",
                            passwordVariable: 'PASSWORD', usernameVariable: 'USERNAME')]) {
                        if (dockerRegistryHost.contains(".svc:5000")) {
                            script.println "[DEBUG] Internal docker registry. Need to port forward"
                            def forwardPort = "15432"
                            def fakeDockerRegistryHost = "localhost:${forwardPort}"
                            imageUrl = imageUrl.replaceAll(dockerRegistryHost, fakeDockerRegistryHost)
                            script.println "[DEBUG] fake image url: ${imageUrl}"
                            def registryNamespace = "openshift-image-registry"
                            def registryPod = script.sh(script: "oc get pods -n ${registryNamespace} " +
                                    "| grep ^image-registry | awk '{ print \$1 }' | head -1", returnStdout: true).replaceAll('\n', '')

                            script.sh "oc port-forward ${registryPod} ${forwardPort}:5000 " +
                                    "-n ${registryNamespace} & sudo docker build --no-cache -t '${imageUrl}' . " +
                                    "&& sudo docker login -u ${script.USERNAME} -p ${script.PASSWORD} ${fakeDockerRegistryHost}" +
                                    "&& sudo docker push ${imageUrl}"
                        } else {
                            script.sh "sudo docker build --no-cache -t '${imageUrl}' . " +
                                    "&& sudo docker login -u ${script.USERNAME} -p ${script.PASSWORD} ${dockerRegistryHost}" +
                                    "&& sudo docker push ${imageUrl}"
                        }
                    }
                }

                new CodebaseImageStreams(context, script)
                        .UpdateOrCreateCodebaseImageStream(outputImagestreamName, imageRepository, context.codebase.isTag)
            }
        }
    }
}

return BuildDockerfileImageDocker
