package org.example.dockerapp;

import java.io.IOException;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws InterruptedException, IOException {

        // Create a Docker client using the default configuration
        DockerClient dockerClient = DockerClientBuilder
                .getInstance(DefaultDockerClientConfig.createDefaultConfigBuilder().build()).build();

        // create a new container from the hello-world image
        CreateContainerResponse container = dockerClient.createContainerCmd("hello-world")
                .withName("hello-world-container")
                .exec();

        // start the container
        dockerClient.startContainerCmd(container.getId()).exec();

        System.out.println(dockerClient.inspectContainerCmd(container.getId()).exec());

        // stop and remove the container
        dockerClient.removeContainerCmd(container.getId()).exec();
    }

}

// wait for the container to finish and redirect the output to the console
// dockerClient.logContainerCmd(container.getId())
// .withStdOut(true)
// .withStdErr(true)
// .exec(new ResultCallbackTemplate<LogContainerResultCallback, Frame>() {
// @Override
// public void onNext(Frame frame) {
// System.out.print(new String(frame.getPayload()));
// }
// }).awaitCompletion(30, TimeUnit.SECONDS);