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
import org.pcap4j.core.PcapHandle.TimestampPrecision;
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

        // Sleep 10 seconds
        Thread.sleep(10000);

        // Get Ip address
        ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
                .getNetworks().values().iterator().next();
        String ipAddress = network.getIpAddress();
        System.out.println("IP Address: " + ipAddress);

        // Start UDP DOS
        UDPDos udp = new UDPDos(ipAddress);
        udp.start();

        // Sleep 60 seconds
        Thread.sleep(60000);

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
            handle = Pcaps.openOffline(pcapFile, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(pcapFile);
        }

        while (true) {
            try {
                Packet packet = handle.getNextPacketEx();
                System.out.println(handle.getTimestamp());
                // System.out.println(packet);
                String packetString = packet.toString();
                System.out.println(packetString);
                // parsePacket(packetString);
                // if (packetString.contains("UDP")) {
                // break;
                // }

            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }

        handle.close();
    }

    private static void parsePacket(String packetString) {
        Pattern ethernetHeaderPattern = Pattern.compile("\\[Ethernet Header \\((\\d+) bytes\\)\\]\n" +
                "  Destination address: ([\\d:]+)\n" +
                "  Source address: ([\\d:]+)\n" +
                "  Type: (\\S+) \\((\\S+)\\)");

        Pattern ipv6HeaderPattern = Pattern.compile("\\[IPv6 Header \\((\\d+) bytes\\)\\]\n" +
                "  Version: (\\d+) \\((\\S+)\\)\n" +
                "  Traffic Class: (\\S+)\\n" +
                "  Flow Label: (\\S+)\\n" +
                "  Payload length: (\\d+) \\[bytes\\]\\n" +
                "  Next Header: (\\d+) \\((\\S+)\\)\n" +
                "  Hop Limit: (\\d+)\\n" +
                "  Source address: (\\S+)\\n" +
                "  Destination address: (\\S+)");

        Pattern icmpv6CommonHeaderPattern = Pattern.compile("\\[ICMPv6 Common Header \\((\\d+) bytes\\)\\]\n" +
                "  Type: (\\d+) \\((\\S+)\\)\n" +
                "  Code: (\\d+) \\((\\S+)\\)\n" +
                "  Checksum: (\\S+)");

        Pattern icmpv6RouterSolicitationHeaderPattern = Pattern
                .compile("\\[ICMPv6 Router Solicitation Header \\((\\d+) bytes\\)\\]\n" + "  Reserved: (\\d+)\\n" +
                        "  Option: \\[Type: (\\d+) \\((\\S+)\\)\\] \\[Length: (\\d+) \\((\\d+) bytes\\)\\] \\[linkLayerAddress: ([\\d:]+)\\]");

        Matcher ethernetHeaderMatcher = ethernetHeaderPattern.matcher(packetString);
        Matcher ipv6HeaderMatcher = ipv6HeaderPattern.matcher(packetString);
        Matcher icmpv6CommonHeaderMatcher = icmpv6CommonHeaderPattern.matcher(packetString);
        Matcher icmpv6RouterSolicitationHeaderMatcher = icmpv6RouterSolicitationHeaderPattern.matcher(packetString);

        if (ethernetHeaderMatcher.find()) {
            int ethernetHeaderSize = Integer.parseInt(ethernetHeaderMatcher.group(1));
            String destinationAddress = ethernetHeaderMatcher.group(2);
            String sourceAddress = ethernetHeaderMatcher.group(3);
            String type = ethernetHeaderMatcher.group(4);
            String typeDescription = ethernetHeaderMatcher.group(5);

            System.out.println("Ethernet Header:");
            System.out.println("  Size: " + ethernetHeaderSize + " bytes");
            System.out.println("  Destination address: " + destinationAddress);
            System.out.println("  Source address: " + sourceAddress);
            System.out.println("  Type: " + type + " (" + typeDescription + ")");
        }

        if (ipv6HeaderMatcher.find()) {
            int ipv6HeaderSize = Integer.parseInt(ipv6HeaderMatcher.group(1));
            int version = Integer.parseInt(ipv6HeaderMatcher.group(2));
            String versionDescription = ipv6HeaderMatcher.group(3);
            String trafficClass = ipv6HeaderMatcher.group(4);
            String flowLabel = ipv6HeaderMatcher.group(5);
            int payloadLength = Integer.parseInt(ipv6HeaderMatcher.group(6));
            int nextHeader = Integer.parseInt(ipv6HeaderMatcher.group(7));
            String nextHeaderDescription = ipv6HeaderMatcher.group(8);
            int hopLimit = Integer.parseInt(ipv6HeaderMatcher.group(9));
            String sourceAddress = ipv6HeaderMatcher.group(10);
            String destinationAddress = ipv6HeaderMatcher.group(11);

            System.out.println("IPv6 Header:");
            System.out.println("  Size: " + ipv6HeaderSize + " bytes");
            System.out.println("  Version: " + version + " (" + versionDescription + ")");
            System.out.println("  Traffic Class: " + trafficClass);
            System.out.println("  Flow Label: " + flowLabel);
            System.out.println("  Payload length: " + payloadLength + " bytes");
            System.out.println("  Next Header: " + nextHeader + " (" + nextHeaderDescription + ")");
            System.out.println("  Hop Limit: " + hopLimit);
            System.out.println("  Source address: " + sourceAddress);
            System.out.println("  Destination address: " + destinationAddress);
        }

        if (icmpv6CommonHeaderMatcher.find()) {
            int icmpv6CommonHeaderSize = Integer.parseInt(icmpv6CommonHeaderMatcher.group(1));
            int type = Integer.parseInt(icmpv6CommonHeaderMatcher.group(2));
            String typeDescription = icmpv6CommonHeaderMatcher.group(3);
            int code = Integer.parseInt(icmpv6CommonHeaderMatcher.group(4));
            String codeDescription = icmpv6CommonHeaderMatcher.group(5);
            String checksum = icmpv6CommonHeaderMatcher.group(6);

            System.out.println("ICMPv6 Common Header:");
            System.out.println("  Size: " + icmpv6CommonHeaderSize + " bytes");
            System.out.println("  Type: " + type + " (" + typeDescription + ")");
            System.out.println(" Code: " + code + " (" + codeDescription + ")");
            System.out.println(" Checksum: " + checksum);
        }
        if (icmpv6RouterSolicitationHeaderMatcher.find()) {
            int reserved = Integer.parseInt(icmpv6RouterSolicitationHeaderMatcher.group(1));
            int optionType = Integer.parseInt(icmpv6RouterSolicitationHeaderMatcher.group(2));
            String optionTypeDescription = icmpv6RouterSolicitationHeaderMatcher.group(3);
            int optionLength = Integer.parseInt(icmpv6RouterSolicitationHeaderMatcher.group(4));
            int optionLengthBytes = Integer.parseInt(icmpv6RouterSolicitationHeaderMatcher.group(5));
            String linkLayerAddress = icmpv6RouterSolicitationHeaderMatcher.group(6);

            System.out.println("ICMPv6 Router Solicitation Header:");
            System.out.println("  Reserved: " + reserved);
            System.out.println("  Option: Type " + optionType + " (" + optionTypeDescription + "), Length "
                    + optionLength + " (" + optionLengthBytes + " bytes), linkLayerAddress " + linkLayerAddress);
        }
    }

}