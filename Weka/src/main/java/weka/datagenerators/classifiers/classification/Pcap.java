package weka.datagenerators.classifiers.classification;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Vector;
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
import com.github.dockerjava.core.command.ExecStartResultCallback;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Option;
import weka.core.RevisionUtils;
import weka.core.Utils;
import weka.datagenerators.ClassificationGenerator;

/**
 * Generates a contexctual dataset of network traffic. The dataset is generated
 * from a simulation of a network traffic. The simulation is done using a
 * docker.
 * The docker container capture the network traffic and save into a pcap file.
 * The pcap file is then parsed to extract the features of the network traffic.
 * It is possible to run some attack on the docker container to generate some
 * specific network traffic.
 * 
 * The available attacks are: UDPDDOS.
 * 
 * The available docker images are:
 * - fersuy/contackgen-ubuntu2204:1.1.0
 * 
 * @author Mathieu Salliot (SanjiKush on GitHub).
 * @author Pierre BLAIS (pierreblais or PierreBls on GitHub).
 * 
 * @version idk.
 */
public class Pcap extends ClassificationGenerator {

    // Dataset attributes
    private static final String[] STRING_DATASET_ATTRIBUTES = {
            "srcIp", "dstIp", "protocol"
    };
    private static final String[] INT_DATASET_ATTRIBUTES = {
            "srcPort", "dstPort", "type", "version", "IHL", "length", "identification", "fragmentOffset", "TTL",
            "headerChecksum", "timeStamp"
    };
    private static final String[] DATASET_ATTRIBUTES = ArrayUtils.addAll(STRING_DATASET_ATTRIBUTES,
            INT_DATASET_ATTRIBUTES);
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
    private static int[] timestamps;

    // Regex patterns
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

    // Generator accepted attribute
    private static final String[] ACCEPTED_DOCKER_IMAGES = {
            "fersuy/contackgen-ubuntu2204:1.1.0"
    };

    // Generator attributes
    protected String dockerImage;
    protected String pcapFullPath;
    protected int duration;
    protected int maxPackets;

    // TimeStamp
    private static Timestamp startTime;

    /**
     * Initialize the generator with the default values.
     */
    public Pcap() {
        super();

        setDockerImage(defaultDockerImage());
        setDuration(defaultDuration());
        setPcapFullPath(defaultPcapFullPath());
        setMaxPackets(defaultMaxPackets());
    }

    /**
     * Returns a string describing this data generator.
     * 
     * @return a description of the generator suitable for displaying in the
     *         explorer/experimenter gui.
     */
    public String globalInfo() {
        return "Generates a contexctual dataset of network traffic. The dataset is generated "
                + "from a simulation of a network traffic. The simulation is done using a docker."
                + "The docker container capture the network traffic and save into a pcap file."
                + "The pcap file is then parsed to extract the features of the network traffic."
                + "It is possible to run some attack on the docker container to generate some "
                + "specific network traffic.\n"
                + "The available attacks are: UDPDDOS.\n"
                + "The available docker images are:\n"
                + "- fersuy/contackgen-ubuntu2204:1.1.0\n";
    }

    /**
     * Returns an enumaratation of the available options.
     * 
     * @return an enumeration of all the available options.
     */
    @Override
    public Enumeration<Option> listOptions() {
        Vector<Option> newVector = enumToVector(super.listOptions());

        newVector.add(new Option("\tThe docker image to use for the simulation. (default: "
                + defaultDockerImage() + ")", "dockerImage", 1, "-dockerImage <dockerImage>"));
        newVector.add(new Option("\tThe network traffic captur duration. (default: "
                + defaultDuration() + ")", "duration", 1, "-duration <duration>"));
        newVector.add(new Option("\tThe pcap directory. (default: "
                + defaultPcapFullPath() + ")", "pcapFullPath", 1, "-pcapFullPath <pcapFullPath>"));
        newVector.add(new Option("\tThe max number of packets to parse. (default: "
                + defaultMaxPackets() + ")", "maxPackets", 1, "-maxPackets <maxPackets>"));

        return newVector.elements();
    }

    /**
     * Parses a given list of options.
     * 
     * @param options the list of options as an array of strings.
     * @throws Exception if an option is not supported.
     */
    @Override
    public void setOptions(String[] options) throws Exception {
        super.setOptions(options);

        // Set the docker image
        String dockerImage = Utils.getOption("dockerImage", options);
        if (dockerImage.length() != 0) {
            setDockerImage(dockerImage);
        } else {
            setDockerImage(defaultDockerImage());
        }

        // Set the duration
        int duration = Integer.parseInt(Utils.getOption("duration", options));
        if (duration != 0) {
            setDuration(duration);
        } else {
            setDuration(defaultDuration());
        }

        // Set the pcap directory
        String pcapDir = Utils.getOption("pcapFullPath", options);
        if (pcapDir.length() != 0) {
            setPcapFullPath(pcapDir);
        } else {
            setPcapFullPath(defaultPcapFullPath());
        }

        // Set the max number of packets
        int maxPackets = Integer.parseInt(Utils.getOption("maxPackets", options));
        if (maxPackets != 0) {
            setMaxPackets(maxPackets);
        } else {
            setMaxPackets(defaultMaxPackets());
        }
    }

    /**
     * Gets the current settings of the generator.
     * 
     * @return an array of strings suitable for passing to setOptions.
     */
    @Override
    public String[] getOptions() {
        Vector<String> newVector = new Vector<String>();
        String[] options = super.getOptions();
        for (int i = 0; i < options.length; i++) {
            newVector.add(options[i]);
        }

        // Add the docker image
        newVector.add("-dockerImage");
        newVector.add(getDockerImage());

        // Add the duration
        newVector.add("-duration");
        newVector.add("" + getDuration());

        // Add the pcap directory
        newVector.add("-pcapFullPath");
        newVector.add(getPcapFullPath());

        // Add the max number of packets
        newVector.add("-maxPackets");
        newVector.add("" + getMaxPackets());

        return newVector.toArray(new String[0]);
    }

    /**
     * returns the default Docker image.
     * 
     * @return the default Docker image.
     */
    protected String defaultDockerImage() {
        return "fersuy/contackgen-ubuntu2204:1.1.0";
    }

    /**
     * returns the default duration.
     * 
     * @return the default duration.
     */
    protected int defaultDuration() {
        return 180;
    }

    /**
     * returns the default pcap directory.
     * 
     * @return the default pcap directory.
     */
    protected String defaultPcapFullPath() {
        return "/tmp/capture.pcap";
    }

    /**
     * returns the default max number of packets.
     * 
     * @return the default max number of packets.
     */
    protected int defaultMaxPackets() {
        return 1000;
    }

    /**
     * Gets the Docker image.
     * 
     * @return the Docker image.
     */
    public String getDockerImage() {
        return dockerImage;
    }

    /**
     * Gets the duration.
     * 
     * @return the duration.
     */
    public int getDuration() {
        return duration;
    }

    /**
     * Gets the pcap directory.
     * 
     * @return the pcap directory.
     */
    public String getPcapFullPath() {
        return pcapFullPath;
    }

    /**
     * Gets the max number of packets.
     * 
     * @return the max number of packets.
     */
    public int getMaxPackets() {
        return maxPackets;
    }

    /**
     * Sets the Docker image.
     * 
     * @param dockerImage the Docker image.
     */
    public void setDockerImage(String dockerImage) {
        if (Arrays.asList(ACCEPTED_DOCKER_IMAGES).contains(dockerImage)) {
            this.dockerImage = dockerImage;
        } else {
            throw new IllegalArgumentException("The docker image " + dockerImage + " is not supported.");
        }
    }

    /**
     * Sets the duration.
     * 
     * @param duration the duration.
     */
    public void setDuration(int duration) {
        this.duration = duration;
    }

    /**
     * Sets the pcap directory.
     * 
     * @param pcapFullPath the pcap directory.
     */
    public void setPcapFullPath(String pcapFullPath) {
        // Check if the pcap directory is not empty
        if (pcapFullPath.length() != 0) {
            this.pcapFullPath = defaultPcapFullPath();
        }

        // Extract the pcap directory
        String pcapDir = pcapFullPath.substring(0, pcapFullPath.lastIndexOf("/"));

        // Convert the pcap directory to a Path object
        Path path = Paths.get(pcapDir);

        // Check if the pcap directory exists
        if (!Files.exists(path) || !Files.isDirectory(path)) {
            // Throw an exception if the pcap directory does not exist
            throw new IllegalArgumentException("The pcap directory " + pcapDir + " does not exist.");
        }

        // Create absolute full path
        this.pcapFullPath = path.toAbsolutePath().toString() + "/"
                + pcapFullPath.substring(pcapFullPath.lastIndexOf("/") + 1);
    }

    /**
     * Sets the max number of packets.
     * 
     * @param maxPackets the max number of packets.
     */
    public void setMaxPackets(int maxPackets) {
        this.maxPackets = maxPackets;
    }

    /**
     * Initializes the format for the dataset produced. Must be called before the
     * generateExample or generateExamples methods are used.
     *
     * Basicaly Re-initializes the random number generator with the given seed. But
     * NOT IN OUR USECASE, we don't use random seed because or datagenration is
     * contexctual and not unitary and reproduceable
     * 
     * @return the format for the dataset
     * @throws Exception if the generating of the format failed
     * @see #getSeed()
     */
    @Override
    public Instances defineDataFormat() throws Exception {
        // Set up the attributes
        ArrayList<Attribute> atts = new ArrayList<Attribute>();
        // for (String attribute : STRING_DATASET_ATTRIBUTES) {
        // atts.add(new Attribute(attribute, (ArrayList<String>) null));
        // }
        // for (String attribute : INT_DATASET_ATTRIBUTES) {
        // atts.add(new Attribute(attribute));
        // }

        // Debug
        for (String attribute : DATASET_ATTRIBUTES) {
            atts.add(new Attribute(attribute));
        }

        m_DatasetFormat = new Instances(getRelationNameToUse(), atts, 0);

        return m_DatasetFormat;
    }

    /**
     * Do nothing because the dataset is already isn't unatrily generated.
     * (basicaly the generateExamples call the generateExample method
     * several times to generate the dataset, in our case the generateExamples
     * will genereted the dataset without unitary and reproduceable action)
     * 
     * @return null
     * @throws Exception if the example could not be generated
     */
    @Override
    public Instance generateExample() throws Exception {
        return null;
    }

    /**
     * Generates a dataset of network traffic.
     * 
     * (Look like our main function)
     * 
     * @return the generated dataset
     * @throws Exception if the format of the dataset is not defined
     * @throws Exception if the dataset could not be generated
     */
    @Override
    public Instances generateExamples() throws Exception {
        // Check if the dataset format is defined
        if (m_DatasetFormat == null) {
            throw new Exception("Dataset format not defined.");
        }

        // Start the docker container
        runDocker(getDockerImage(), getDuration(), getPcapFullPath());

        Instances result = new Instances(m_DatasetFormat, 0);
        double[] atts;
        for (int i = 0; i < getMaxPackets(); i++) {
            // Equivalent to the generateExample method
            Instance instance = null;
            atts = new double[] {
                    srcIps[i], dstIps[i], srcPorts[i], dstPorts[i], types[i], versions[i],
                    IHLs[i], lengths[i], identifications[i],
                    fragmentOffsets[i], TTLs[i], protocols[i], headerChecksums[i], timestamps[i] };
            instance = new DenseInstance(1.0, atts);
            instance.setDataset(m_DatasetFormat);

            result.add(instance);
        }

        return result;
    }

    /**
     * Generates a comment string that documentates the data generator. By default
     * this string is added at the beginning of the produced output as ARFF file
     * type, next after the options.
     * 
     * @return string contains info about the generated rules
     */
    @Override
    public String generateStart() throws Exception {
        return "";
    }

    /**
     * Generates a comment string that documentates the data generator. By default
     * this string is added at the end of the produced output as ARFF file type.
     * 
     * @return string contains info about the generated rules
     */
    @Override
    public String generateFinished() throws Exception {
        return null;
    }

    /**
     * I not understand what is this method for.
     */
    @Override
    public boolean getSingleModeFlag() throws Exception {
        return false;
    }

    /**
     * Returns the revision string.
     * 
     * @return the revision
     */
    @Override
    public String getRevision() {
        return RevisionUtils.extract("$Revision: 99999 $");
    }

    /**
     * Main method for running this data generator.
     * 
     * @param args the commandline arguments
     */
    public static void main(String[] args) {
        runDataGenerator(new Pcap(), args);
    }

    // ========================================================================
    // The following methods should be implemented in another class
    // ========================================================================

    /**
     * Parse network traffic from a pcap file.
     * 
     * @param pcapFile the pcap file to parse
     */
    private static void readPcap(String pcapFile) throws PcapNativeException, NotOpenException {
        System.out.println("Read pcap file: " + pcapFile + "");
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
                    // get packet timestamp format since the beginning of the capture
                    long timeDiffInMillis = handle.getTimestamp().getTime() - startTime.getTime();
                    timestamps = ArrayUtils.add(timestamps, (int) timeDiffInMillis);
                }

            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }

        handle.close();
    }

    /**
     * Parse a packet from a pcap file.
     * 
     * @param packet the packet to parse
     */
    private static void parsePacket(String packet) {
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

    /**
     * Run a docker container.
     * Execute the payload.sh script in the container.
     * Execute the attack in the container.
     * Copy the pcap file from the container to the host.
     * Stop the container.
     * Remove the container.
     * Parse the pcap file.
     * 
     * @param dockerImage the docker image to run
     */
    private static void runDocker(String dockerImage, int duration, String pcapFullPath)
            throws InterruptedException, IOException {
        System.out.println("Run Docker");

        // Docker parameters
        String containerName = "contackgen-ubuntu2204";
        String containerFile = "/data/capture.pcap";

        // Get the Docker client
        System.out.println("Get Docker client");
        DockerClient dockerClient = DockerClientBuilder.getInstance().build();

        // Create container
        System.out.println("Create Docker container");
        try (CreateContainerCmd createContainer = dockerClient
                .createContainerCmd(dockerImage).withName(containerName)) {
            createContainer.withTty(true);
            createContainer.exec();
        }

        // Start container
        System.out.println("Start Docker container");
        dockerClient.startContainerCmd(containerName).exec();

        // Sleep 2 seconds
        Thread.sleep(2000);

        // Execute the payload.sh in the container
        System.out.println("Execute payload.sh in the container");
        dockerClient
                .execStartCmd(dockerClient.execCreateCmd(containerName).withAttachStdout(true)
                        .withCmd("bash", "-c", "./payload.sh -d " + duration).exec().getId())
                .exec(new ExecStartResultCallback(System.out, System.err));

        // Sleep 2 seconds
        Thread.sleep(2000);

        // Get Ip address
        System.out.println("Get IP address");
        ContainerNetwork network = dockerClient.inspectContainerCmd(containerName).exec().getNetworkSettings()
                .getNetworks().values().iterator().next();
        String ipAddress = network.getIpAddress();
        System.out.println("IP Address: " + ipAddress);

        // Start UDP DOS
        System.out.println("Start UDP DOS");
        UDPDos udp = new UDPDos(ipAddress);
        udp.start();
        startTime = new Timestamp(System.currentTimeMillis());

        // Sleep 20 seconds
        Thread.sleep(duration * 1000);

        // Copy file from container
        try (TarArchiveInputStream tarStream = new TarArchiveInputStream(
                dockerClient.copyArchiveFromContainerCmd(containerName,
                        containerFile).exec())) {
            unTar(tarStream, new File(pcapFullPath));
        }

        // Stop container
        System.out.println("Stop the container");
        dockerClient.killContainerCmd(containerName).exec();

        // Remove container
        System.out.println("Remove container");
        dockerClient.removeContainerCmd(containerName).exec();

        try {
            readPcap(pcapFullPath);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
    }

    /**
     * Untar a file.
     * 
     * @param tis      the tar input stream
     * @param destFile the destination file
     * @throws IOException
     */
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
}
