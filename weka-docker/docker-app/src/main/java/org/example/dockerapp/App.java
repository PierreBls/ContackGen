package org.example.dockerapp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.core.DockerClientBuilder;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws InterruptedException, IOException {
        // Data
        String imageId = "fersuy/contackgen-ubuntu:22.04";
        String containerName = "contackgen-ubuntu";
        String containerFile = "/data/capture.pcap";
        String hostFile = "./capture.pcap";

        // Docker client
        DockerClient dockerClient = DockerClientBuilder.getInstance().build();

        // Create container
        try (CreateContainerCmd createContainer = dockerClient
                .createContainerCmd(imageId).withName(containerName)) {
            createContainer.withTty(true);
            createContainer.exec();
        }

        // Start container
        dockerClient.startContainerCmd(containerName).exec();

        // Get Ip address
        ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
                .getNetworks().values().iterator().next();
        String ipAddress = network.getIpAddress();
        System.out.println("IP Address: " + ipAddress);
        UDPDos udp = new UDPDos(ipAddress);
        udp.start();

        // Sleep 70 seconds
        Thread.sleep(70000);

        // Copy file from container
        try (TarArchiveInputStream tarStream = new TarArchiveInputStream(
                dockerClient.copyArchiveFromContainerCmd(containerName,
                        containerFile).exec())) {
            unTar(tarStream, new File(hostFile));
        }

        // Stop container
        dockerClient.killContainerCmd(containerName).exec();

        // Remove container
        dockerClient.removeContainerCmd(containerName).exec();
    }

    public static void unTar(TarArchiveInputStream tis, File destFile)
            throws IOException {
        TarArchiveEntry tarEntry = null;
        while ((tarEntry = tis.getNextTarEntry()) != null) {
            if (tarEntry.isDirectory()) {
                if (!destFile.exists()) {
                    destFile.mkdirs();
                }
            } else {
                FileOutputStream fos = new FileOutputStream(destFile);
                IOUtils.copy(tis, fos);
                fos.close();
            }
        }
        tis.close();
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