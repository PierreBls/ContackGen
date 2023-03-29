package weka.datagenerators.classifiers.classification;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.core.DockerClientBuilder;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.RevisionUtils;
import weka.datagenerators.ClassificationGenerator;

public class Pcap extends ClassificationGenerator {

    private static int[] srcIps;
    private static int[] dstIps;
    private static int[] srcPorts;
    private static int[] dstPorts;
    private static int[] types;
    private static int[] versions;
    private static int[] IHLs;
    private static int[] lengths;
    private static int[] identifications;
    private static int[] fragmentOffsets;
    private static int[] TTLs;
    private static int[] protocols;
    private static int[] headerChecksums;

    private static int numInstances = 100;

    // REGEXES
    private static final Pattern DEST_ADDR_PATTERN = Pattern.compile("Destination address: /([\\d.]+)");
    private static final Pattern SRC_ADDR_PATTERN = Pattern.compile("Source address: /([\\d.]+)");
    private static final Pattern SRC_PORT_PATTERN = Pattern.compile("Source port: (\\d+)");
    private static final Pattern DEST_PORT_PATTERN = Pattern.compile("Destination port: (\\d+)");
    private static final Pattern TYPE_PATTERN = Pattern.compile("Type: (0x[\\da-fA-F]+)");
    private static final Pattern VERSION_PATTERN = Pattern.compile("Version: (\\d+)");
    private static final Pattern IHL_PATTERN = Pattern.compile("IHL: (\\d+)");
    private static final Pattern LENGTH_PATTERN = Pattern.compile("Length: (\\d+)");
    private static final Pattern IDENTIFICATION_PATTERN = Pattern.compile("Identification: (\\d+)");
    private static final Pattern FRAGMENT_OFFSET_PATTERN = Pattern.compile("Fragment offset: (\\d+)");
    private static final Pattern TTL_PATTERN = Pattern.compile("TTL: (\\d+)");
    private static final Pattern PROTOCOL_PATTERN = Pattern.compile("Protocol: (\\d+)");
    private static final Pattern HEADER_CHECKSUM_PATTERN = Pattern.compile("Header checksum: (0x[\\da-fA-F]+)");

    public Pcap() {
        super();
    }

    public String globalInfo() {
        return "A data generator that produces data from a pcap file.";
    }

    @Override
    public Instances defineDataFormat() throws Exception {
        ArrayList<Attribute> atts = new ArrayList<Attribute>();

        atts.add(new Attribute("ipSrc"));
        atts.add(new Attribute("ipDst"));
        atts.add(new Attribute("portSrc"));
        atts.add(new Attribute("portDst"));
        atts.add(new Attribute("type"));
        atts.add(new Attribute("version"));
        atts.add(new Attribute("IHL"));
        atts.add(new Attribute("Length"));
        atts.add(new Attribute("Identification"));
        atts.add(new Attribute("fragmentOffset"));
        atts.add(new Attribute("TTL"));
        atts.add(new Attribute("protocol"));
        atts.add(new Attribute("headerChecksum"));

        m_DatasetFormat = new Instances(getRelationNameToUse(), atts, 0);

        // System.out.println(m_DatasetFormat.toString());
        return m_DatasetFormat;
    }

    @Override
    public Instance generateExample() throws Exception {
        return null;
    }

    @Override
    public Instances generateExamples() throws Exception {
        System.out.println("Running Docker...");
        runDocker();

        if (m_DatasetFormat == null) {
            throw new Exception("Dataset format not defined.");
        }

        Instances result = new Instances(m_DatasetFormat, 0);
        double[] atts;

        for (int i = 0; i < numInstances; i++) {
            Instance instance = null;
            atts = new double[] {
                    srcIps[i], dstIps[i], srcPorts[i], dstPorts[i], types[i], versions[i],
                    IHLs[i], lengths[i], identifications[i],
                    fragmentOffsets[i], TTLs[i], protocols[i], headerChecksums[i] };
            instance = new DenseInstance(1.0, atts);
            instance.setDataset(m_DatasetFormat);

            result.add(instance);
        }

        return result;
    }

    @Override
    public String generateStart() throws Exception {
        return "";
    }

    @Override
    public String generateFinished() throws Exception {
        return null;
    }

    @Override
    public boolean getSingleModeFlag() throws Exception {
        return false;
    }

    @Override
    public String getRevision() {
        return RevisionUtils.extract("$Revision: 99999 $");
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
                    parsePacket(packetString);
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
        if (packet.contains("UDP")) {
            Matcher destAddrMatcher = DEST_ADDR_PATTERN.matcher(packet);
            if (destAddrMatcher.find()) {
                String ip = destAddrMatcher.group(1);
                int ipInt = Integer.parseInt(ip.replace(".", ""));
                dstIps = ArrayUtils.add(dstIps, ipInt);
                // System.out.println("ipsrc: " + ipInt);
            }

            Matcher srcAddrMatcher = SRC_ADDR_PATTERN.matcher(packet);
            if (srcAddrMatcher.find()) {
                String ip = srcAddrMatcher.group(1);
                int ipInt = Integer.parseInt(ip.replace(".", ""));
                srcIps = ArrayUtils.add(srcIps, ipInt);
                // System.out.println("ipdst: " + ipInt);
            }

            Matcher typeMatcher = TYPE_PATTERN.matcher(packet);
            if (typeMatcher.find()) {
                String typeHex = typeMatcher.group(1);
                // System.out.println("typeHex: " + typeHex);
                types = ArrayUtils.add(types, Integer.parseInt(typeHex.substring(2), 16));
                // System.out.println("type: " + Integer.parseInt(typeHex.substring(2), 16));
            }
            Matcher srcPortMatcher = SRC_PORT_PATTERN.matcher(packet);
            if (srcPortMatcher.find()) {
                srcPorts = ArrayUtils.add(srcPorts, Integer.parseInt(srcPortMatcher.group(1)));
                // System.out.println("portsrc: " + srcPortMatcher.group(1));
            }

            Matcher destPortMatcher = DEST_PORT_PATTERN.matcher(packet);
            if (destPortMatcher.find()) {
                dstPorts = ArrayUtils.add(dstPorts, Integer.parseInt(destPortMatcher.group(1)));
                // System.out.println("portdst: " + destPortMatcher.group(1));
            }

            Matcher versionMatcher = VERSION_PATTERN.matcher(packet);
            if (versionMatcher.find()) {
                versions = ArrayUtils.add(versions, Integer.parseInt(versionMatcher.group(1)));
                // System.out.println("version: " + versionMatcher.group(1));
            }

            Matcher ihlMatcher = IHL_PATTERN.matcher(packet);
            if (ihlMatcher.find()) {
                IHLs = ArrayUtils.add(IHLs, Integer.parseInt(ihlMatcher.group(1)));
                // System.out.println("ihl: " + ihlMatcher.group(1));
            }

            Matcher lengthMatcher = LENGTH_PATTERN.matcher(packet);
            if (lengthMatcher.find()) {
                lengths = ArrayUtils.add(lengths, Integer.parseInt(lengthMatcher.group(1)));
                // System.out.println("length: " + lengthMatcher.group(1));
            }

            Matcher identificationMatcher = IDENTIFICATION_PATTERN.matcher(packet);
            if (identificationMatcher.find()) {
                identifications = ArrayUtils.add(identifications, Integer.parseInt(identificationMatcher.group(1)));
                // System.out.println("identification: " + identificationMatcher.group(1));
            }

            Matcher fragmentOffsetMatcher = FRAGMENT_OFFSET_PATTERN.matcher(packet);
            if (fragmentOffsetMatcher.find()) {
                fragmentOffsets = ArrayUtils.add(fragmentOffsets, Integer.parseInt(fragmentOffsetMatcher.group(1)));
                // System.out.println("fragmentOffset: " + fragmentOffsetMatcher.group(1));
            }

            Matcher ttlMatcher = TTL_PATTERN.matcher(packet);
            if (ttlMatcher.find()) {
                TTLs = ArrayUtils.add(TTLs, Integer.parseInt(ttlMatcher.group(1)));
                // System.out.println("ttl: " + ttlMatcher.group(1));
            }

            Matcher protocolMatcher = PROTOCOL_PATTERN.matcher(packet);
            if (protocolMatcher.find()) {
                protocols = ArrayUtils.add(protocols, Integer.parseInt(protocolMatcher.group(1)));
                // System.out.println("protocol: " + protocolMatcher.group(1));
            }

            Matcher headerChecksumMatcher = HEADER_CHECKSUM_PATTERN.matcher(packet);
            if (headerChecksumMatcher.find()) {
                String headerChecksumHex = headerChecksumMatcher.group(1);
                headerChecksums = ArrayUtils.add(headerChecksums, Integer.parseInt(headerChecksumHex.substring(2), 16));
                // System.out.println("headerChecksum: " +
                // Integer.parseInt(headerChecksumHex.substring(2), 16));
            }
        }

    }

    private static void runDocker() throws InterruptedException, IOException {
        // Data
        String imageId = "fersuy/contackgen-ubuntu2204:1.0.0";
        String containerName = "contackgen-ubuntu2204";
        String containerFile = "/data/capture.pcap";
        String hostFile = "src/main/java/weka/datagenerators/classifiers/classification/capture.pcap";

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
        System.out.println("Stopping container ...");
        dockerClient.killContainerCmd(containerName).exec();

        // Remove container
        System.out.println("Removing container ...");
        dockerClient.removeContainerCmd(containerName).exec();

        try {
            System.out.println("Reading pcap ...");
            readPcap(hostFile);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }

    private static void unTar(TarArchiveInputStream tis, File destFile) throws IOException {
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

    public static void main(String[] args) {
        runDataGenerator(new Pcap(), args);
    }

}
