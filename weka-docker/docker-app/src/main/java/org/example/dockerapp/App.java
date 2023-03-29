package org.example.dockerapp;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.core.DockerClientBuilder;

/**
 * Hello world!
 */
public class App {

    // REGEXES
    private static final Pattern DEST_ADDR_PATTERN = Pattern.compile("Destination address: /([\\d.]+)");
    private static final Pattern SRC_ADDR_PATTERN = Pattern.compile("Source address: /([\\d.]+)");
    private static final Pattern SRC_PORT_PATTERN = Pattern.compile("Source port: (\\d+)");
    private static final Pattern DEST_PORT_PATTERN = Pattern.compile("Destination port: (\\d+)");

    public static void main(String[] args) throws InterruptedException, IOException {
        // Data
        String imageId = "fersuy/contackgen-ubuntu2204:1.0.0";
        String containerName = "contackgen-ubuntu2204";
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

        // Sleep 2 seconds
        Thread.sleep(2000);

        // Get Ip address
        ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
                .getNetworks().values().iterator().next();
        String ipAddress = network.getIpAddress();
        System.out.println("IP Address: " + ipAddress);

        // Start UDP DOS
        UDPDos udp = new UDPDos(ipAddress);
        udp.start();

        // Sleep 20 seconds
        Thread.sleep(20000);

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

        try {
            readPcap(hostFile);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }

    private static void unTar(TarArchiveInputStream tis, File destFile)
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

    private static void readPcap(String pcapFile) throws PcapNativeException, NotOpenException {

        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(pcapFile, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(pcapFile);
        }

        while (true) {
            try {
                Packet packet = handle.getNextPacketEx();
                String packetString = packet.toString();
                if (packetString.contains("UDP")) {
                    // parsePacket(packetString);
                    System.out.println(packetString);
                }

            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }

        handle.close();
    }

    private static void parsePacket(String packet) {
        Matcher destAddrMatcher = DEST_ADDR_PATTERN.matcher(packet);
        if (destAddrMatcher.find()) {
            System.out.println("Destination address: " + destAddrMatcher.group(1));
        }

        Matcher srcAddrMatcher = SRC_ADDR_PATTERN.matcher(packet);
        if (srcAddrMatcher.find()) {
            System.out.println("Source address: " + srcAddrMatcher.group(1));
        }

        Matcher srcPortMatcher = SRC_PORT_PATTERN.matcher(packet);
        if (srcPortMatcher.find()) {
            System.out.println("Source port: " + srcPortMatcher.group(1));
        }

        Matcher destPortMatcher = DEST_PORT_PATTERN.matcher(packet);
        if (destPortMatcher.find()) {
            System.out.println("Destination port: " + destPortMatcher.group(1));
        }
    }

}