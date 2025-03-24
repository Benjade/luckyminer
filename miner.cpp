// miner.cpp
// Requirements: apt install g++ libssl-dev nlohmann-json3-dev
// Compile: g++ miner.cpp -o miner -lssl -lcrypto -std=c++11 -pthread
// Usage: ./miner [pool_address] [pool_port] [payout_address] [num_mining_threads]

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <random>
#include <fstream>
#include <cerrno>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// Forward declaration for submitBlock
void submitBlock(const std::string &address, const std::string &job_id,
                 const std::string &extranonce2, const std::string &ntime,
                 const std::string &nonce);

// Global variables for command-line arguments
std::string g_poolIP;
std::string g_port;
std::string g_payoutAddress;
unsigned int g_numMiningThreads = 0; // if 0, use hardware_concurrency()

// =======================
// Global context (similar to context.py)
// =======================
struct Context {
    std::atomic<bool> fShutdown {false};
    int local_height = 0;
    std::unordered_map<int, double> nHeightDiff;
    
    std::string updatedPrevHash;
    
    // Mining job data
    std::string job_id;
    std::string prevhash;
    std::string coinb1;
    std::string coinb2;
    std::vector<std::string> merkle_branch;
    std::string version;
    std::string nbits;
    std::string ntime;
    bool clean_jobs = false;
    
    std::string sub_details;
    std::string extranonce1;
    std::string extranonce2; // will be generated randomly
    int extranonce2_size = 0;
    
    // Global notification message
    std::string globalNotification;
    
    int sock_fd = -1;
    
    std::mutex mtx; // to protect shared variables
};

Context ctx;

// Global vector to store each mining thread's status
std::vector<std::string> miningStatuses;
std::mutex statusMutex;

// Log file (all entries are logged with newline)
std::ofstream logFile("miner.log", std::ios::app);

// Mutex to protect stdout printing
std::mutex printMutex;

// The logg() function writes to the log file, updates the global notification,
// and prints the message immediately to stdout.
void logg(const std::string &msg) {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string fullMsg = std::string("[*] ") + msg;
    logFile << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S")
            << " " << fullMsg << std::endl;
    logFile.flush();
    {
        std::lock_guard<std::mutex> lock(ctx.mtx);
        ctx.globalNotification = fullMsg;
    }
    std::lock_guard<std::mutex> lock(printMutex);
    std::cout << fullMsg << std::endl;
}

// Signal handling for clean termination
void signalHandler(int signum) {
    ctx.fShutdown = true;
    std::lock_guard<std::mutex> lock(printMutex);
    std::cout << "\nTerminating miner, please wait..." << std::endl;
}

// Utility conversion functions
std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<unsigned char> &bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes)
        ss << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}

std::vector<unsigned char> doubleSHA256(const std::vector<unsigned char> &data) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash1);
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    return std::vector<unsigned char>(hash2, hash2 + SHA256_DIGEST_LENGTH);
}

// Compute target from nbits (target = (nbits[2:] + "00" * (int(nbits[:2],16)-3)).zfill(64))
std::string computeTarget(const std::string &nbits) {
    if(nbits.size() != 8) return "";
    int exponent = std::stoi(nbits.substr(0, 2), nullptr, 16);
    std::string mantissa = nbits.substr(2);
    std::string target = mantissa;
    int zerosToAppend = exponent - 3;
    for (int i = 0; i < zerosToAppend; i++) {
        target += "00";
    }
    while (target.size() < 64) {
        target = "0" + target;
    }
    return target;
}

// Read a line from a socket (until '\n')
std::string readLineFromSocket(int sock_fd) {
    std::string line;
    char ch;
    while (recv(sock_fd, &ch, 1, 0) == 1) {
        if (ch == '\n') break;
        line.push_back(ch);
    }
    return line;
}

// -------------------------
// Definition of submitBlock
// -------------------------
void submitBlock(const std::string &address, const std::string &job_id,
                 const std::string &extranonce2, const std::string &ntime,
                 const std::string &nonce) {
    json submission;
    submission["id"] = 1;
    submission["method"] = "mining.submit";
    submission["params"] = { address, job_id, extranonce2, ntime, nonce };
    std::string payload = submission.dump() + "\n";
    send(ctx.sock_fd, payload.c_str(), payload.size(), 0);
    logg("Block submitted to pool. Payload: " + payload);
    std::string response = readLineFromSocket(ctx.sock_fd);
    logg("Pool response: " + response);
}

// =======================
// Display function: updates the status of each mining thread on its own line.
// This function continuously refreshes the area reserved for status (from line 8 onward).
void displayStatusThread() {
    const int startupLines = 7; // number of lines reserved for startup messages
    while (!ctx.fShutdown) {
        {
            std::lock_guard<std::mutex> lock(printMutex);
            // Move cursor to line 8 and clear from that line to end of screen
            std::cout << "\033[8;1H" << "\033[J";
            {
                std::lock_guard<std::mutex> lock(statusMutex);
                for (size_t i = 0; i < miningStatuses.size(); i++) {
                    std::cout << "Thread " << i+1 << ": " << miningStatuses[i] << std::endl;
                }
            }
            std::cout.flush();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// =======================
// Mining thread
// Each mining thread uses its index (threadID) to update its own status in the global vector.
void miningThread(unsigned int threadID) {
    {
        std::lock_guard<std::mutex> lock(statusMutex);
        if(threadID >= miningStatuses.size())
            miningStatuses.resize(threadID+1);
        miningStatuses[threadID] = "Waiting for job data...";
    }
    logg("Mining thread " + std::to_string(threadID+1) + " started.");
    
    // Wait until job data is set
    while (!ctx.fShutdown) {
        {
            std::lock_guard<std::mutex> lock(ctx.mtx);
            if (!ctx.job_id.empty() && !ctx.coinb1.empty() && !ctx.coinb2.empty())
                break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (ctx.fShutdown) return;
    
    // Generate random extranonce2
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 0xFFFFFFFF);
    unsigned int randVal = dis(gen);
    {
        std::lock_guard<std::mutex> lock(ctx.mtx);
        std::stringstream ss;
        ss << std::hex << std::setw(ctx.extranonce2_size * 2)
           << std::setfill('0') << randVal;
        ctx.extranonce2 = ss.str();
    }
    
    // Build coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase;
    {
        std::lock_guard<std::mutex> lock(ctx.mtx);
        coinbase = ctx.coinb1 + ctx.extranonce1 + ctx.extranonce2 + ctx.coinb2;
    }
    auto coinbaseBytes = hexToBytes(coinbase);
    auto coinbaseHash = doubleSHA256(coinbaseBytes);
    
    // Compute Merkle root
    std::vector<unsigned char> merkleRoot = coinbaseHash;
    {
        std::lock_guard<std::mutex> lock(ctx.mtx);
        for (const auto &branch : ctx.merkle_branch) {
            auto branchBytes = hexToBytes(branch);
            std::vector<unsigned char> data;
            data.insert(data.end(), merkleRoot.begin(), merkleRoot.end());
            data.insert(data.end(), branchBytes.begin(), branchBytes.end());
            merkleRoot = doubleSHA256(data);
        }
    }
    std::string merkleRootHex = bytesToHex(merkleRoot);
    std::string merkleLE;
    for (int i = merkleRootHex.size(); i > 0; i -= 2) {
        merkleLE += merkleRootHex.substr(i - 2, 2);
    }
    
    // Compute target from nbits
    std::string target;
    {
        std::lock_guard<std::mutex> lock(ctx.mtx);
        target = computeTarget(ctx.nbits);
    }
    logg("Thread " + std::to_string(threadID+1) + " starting mining on block: " + ctx.prevhash);
    
    unsigned int nonce = 0;
    const unsigned int updateInterval = 1000000;
    auto lastTime = std::chrono::high_resolution_clock::now();
    double bestDifficulty = 0.0;
    
    while (!ctx.fShutdown) {
        // Build block header: version + prevhash + merkle root + ntime + nbits + nonce
        std::string version, prevhash, ntime, nbits;
        {
            std::lock_guard<std::mutex> lock(ctx.mtx);
            version = ctx.version;
            prevhash = ctx.prevhash;
            ntime = ctx.ntime;
            nbits = ctx.nbits;
        }
        std::stringstream header;
        header << version << prevhash << merkleLE << ntime << nbits;
        std::stringstream nonceStream;
        nonceStream << std::hex << std::setw(8) << std::setfill('0') << nonce;
        header << nonceStream.str();
        std::string blockHeaderHex = header.str();
        
        auto headerBytes = hexToBytes(blockHeaderHex);
        auto hashBytes = doubleSHA256(headerBytes);
        std::string hashHex = bytesToHex(hashBytes);
        std::string hashLE;
        for (int i = hashHex.size(); i > 0; i -= 2)
            hashLE += hashHex.substr(i - 2, 2);
        
        // Update this thread's status
        {
            std::lock_guard<std::mutex> lock(statusMutex);
            std::stringstream ss;
            ss << "Hashrate: " << std::fixed << std::setprecision(2);
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastTime).count();
            double hr = updateInterval / (elapsed > 0 ? elapsed : 1);
            ss << hr << " hash/s | Best Diff: " << bestDifficulty << " | Nonce: " << nonce;
            miningStatuses[threadID] = ss.str();
        }
        
        if (hashLE < target) {
            logg("Thread " + std::to_string(threadID+1) + " solved block! Nonce: " + nonceStream.str());
            logg("Hash found: " + hashLE);
            {
                std::lock_guard<std::mutex> lock(ctx.mtx);
                // Use the payout address passed as argument
                submitBlock(g_payoutAddress, ctx.job_id, ctx.extranonce2, ctx.ntime, nonceStream.str());
            }
            break;
        }
        
        int zeros = 0;
        for (char c : hashLE) {
            if (c == '0') zeros++;
            else break;
        }
        double currentDiff = zeros;
        if (currentDiff > bestDifficulty)
            bestDifficulty = currentDiff;
        
        if (nonce % updateInterval == 0) {
            lastTime = std::chrono::high_resolution_clock::now();
        }
        nonce++;
    }
}

// =======================
// Block listener thread (Stratum)
// =======================
void blockListenerThread() {
    logg("Block listener thread started.");
    
    // Use command-line parameters
    const char* poolIP = g_poolIP.c_str();
    
    ctx.sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx.sock_fd < 0) {
        logg("Error creating socket");
        ctx.fShutdown = true;
        return;
    }
    
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rv = getaddrinfo(poolIP, g_port.c_str(), &hints, &servinfo);
    if (rv != 0) {
        logg("DNS resolution error: " + std::string(gai_strerror(rv)));
        ctx.fShutdown = true;
        return;
    }
    
    bool connected = false;
    for(p = servinfo; p != nullptr; p = p->ai_next) {
        if (connect(ctx.sock_fd, p->ai_addr, p->ai_addrlen) == -1)
            continue;
        connected = true;
        break;
    }
    freeaddrinfo(servinfo);
    
    if (!connected) {
        logg("Connection to pool failed");
        ctx.fShutdown = true;
        return;
    }
    logg("Connected to pool.");
    
    // Send subscription message
    json subscribeMsg;
    subscribeMsg["id"] = 1;
    subscribeMsg["method"] = "mining.subscribe";
    subscribeMsg["params"] = json::array();
    std::string subPayload = subscribeMsg.dump() + "\n";
    send(ctx.sock_fd, subPayload.c_str(), subPayload.size(), 0);
    
    std::string responseLine = readLineFromSocket(ctx.sock_fd);
    try {
        auto j = json::parse(responseLine);
        if(j.contains("result") && j["result"].is_array() && j["result"].size() >= 3) {
            {
                std::lock_guard<std::mutex> lock(ctx.mtx);
                ctx.extranonce1 = j["result"][1].get<std::string>();
                ctx.extranonce2_size = j["result"][2].get<int>();
                ctx.globalNotification = "Subscription OK";
            }
            logg("Subscription OK, extranonce1: " + ctx.extranonce1 +
                 " size: " + std::to_string(ctx.extranonce2_size));
        } else {
            logg("Unexpected subscription response format.");
        }
    } catch (std::exception &e) {
        logg("Error parsing subscription JSON: " + std::string(e.what()));
    }
    
    // Send authorization message
    std::string address = g_payoutAddress; // payout address used for authorization if needed
    json authMsg;
    authMsg["id"] = 2;
    authMsg["method"] = "mining.authorize";
    authMsg["params"] = { address, "password" };
    std::string authPayload = authMsg.dump() + "\n";
    send(ctx.sock_fd, authPayload.c_str(), authPayload.size(), 0);
    
    responseLine = readLineFromSocket(ctx.sock_fd);
    try {
        auto j = json::parse(responseLine);
        if(j.contains("method") && j["method"] == "mining.notify") {
            auto params = j["params"];
            std::lock_guard<std::mutex> lock(ctx.mtx);
            ctx.job_id   = params[0].get<std::string>();
            ctx.prevhash = params[1].get<std::string>();
            ctx.coinb1   = params[2].get<std::string>();
            ctx.coinb2   = params[3].get<std::string>();
            ctx.merkle_branch.clear();
            for (auto &el : params[4])
                ctx.merkle_branch.push_back(el.get<std::string>());
            ctx.version  = params[5].get<std::string>();
            ctx.nbits    = params[6].get<std::string>();
            ctx.ntime    = params[7].get<std::string>();
            ctx.clean_jobs = params[8].get<bool>();
            ctx.updatedPrevHash = ctx.prevhash;
            ctx.globalNotification = "New job received: " + ctx.job_id;
        }
    } catch (...) {
        logg("Error parsing authorization/job JSON");
    }
    
    // Loop to listen for new jobs
    while (!ctx.fShutdown) {
        std::string line = readLineFromSocket(ctx.sock_fd);
        if (line.empty()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        try {
            auto j = json::parse(line);
            if(j.contains("method") && j["method"] == "mining.notify") {
                auto params = j["params"];
                std::lock_guard<std::mutex> lock(ctx.mtx);
                ctx.job_id   = params[0].get<std::string>();
                ctx.prevhash = params[1].get<std::string>();
                ctx.coinb1   = params[2].get<std::string>();
                ctx.coinb2   = params[3].get<std::string>();
                ctx.merkle_branch.clear();
                for (auto &el : params[4])
                    ctx.merkle_branch.push_back(el.get<std::string>());
                ctx.version  = params[5].get<std::string>();
                ctx.nbits    = params[6].get<std::string>();
                ctx.ntime    = params[7].get<std::string>();
                ctx.clean_jobs = params[8].get<bool>();
                ctx.updatedPrevHash = ctx.prevhash;
                ctx.globalNotification = "New job received: " + ctx.job_id;
            }
        } catch (...) {
            logg("Error parsing JSON in listener thread");
        }
    }
    
    close(ctx.sock_fd);
    logg("Listener thread terminated.");
}

// =======================
// Main
// =======================
int main(int argc, char* argv[]) {
    // Process command-line arguments
    // Usage: ./miner [pool_address] [pool_port] [payout_address] [num_mining_threads]
    if (argc >= 2)
        g_poolIP = argv[1];
    else
        g_poolIP = "solo.ckpool.org";
    
    if (argc >= 3)
        g_port = argv[2];
    else
        g_port = "3333";
    
    if (argc >= 4)
        g_payoutAddress = argv[3];
    else
        g_payoutAddress = "1Bitcoinfr7ZVB1cFVgLJJcweVt8JR2Z3o";
    
    g_numMiningThreads = std::thread::hardware_concurrency();
    if (argc >= 5)
        g_numMiningThreads = std::stoi(argv[4]);
    
    logg("Starting Bitcoin Miner in C++");
    logg("Pool: " + g_poolIP + ":" + g_port);
    logg("Payout address: " + g_payoutAddress);
    logg("Using " + std::to_string(g_numMiningThreads) + " mining threads");
    
    // Start the block listener thread
    std::thread listener(blockListenerThread);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // Initialize the mining status vector
    {
        std::lock_guard<std::mutex> lock(statusMutex);
        miningStatuses.resize(g_numMiningThreads, "Waiting...");
    }
    
    // Print startup messages (they remain at top)
    {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << "===================================================================" << std::endl;
    }
    
    // Reserve the first 7 lines for startup messages by printing 7 blank lines
    {
        std::lock_guard<std::mutex> lock(printMutex);
        for (int i = 0; i < 7; i++)
            std::cout << std::endl;
    }
    
    // Start a display thread to update each mining thread's status on its own line,
    // starting from line 8 (without erasing the startup messages)
    std::thread displayThread(displayStatusThread);
    
    // Start mining threads
    std::vector<std::thread> miningThreads;
    for (unsigned int i = 0; i < g_numMiningThreads; i++) {
        miningThreads.emplace_back(miningThread, i);
    }
    
    for (auto &t : miningThreads)
        t.join();
    
    listener.join();
    ctx.fShutdown = true;
    displayThread.join();
    
    logg("Miner stopped.");
    return 0;
}
