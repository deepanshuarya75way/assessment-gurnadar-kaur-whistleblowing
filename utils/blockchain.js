const crypto = require('crypto');
const pinataSDK = require('@pinata/sdk');
const { ethers } = require('ethers');
const stream = require('stream');
const logger = require('./logger');

// ─── In-Memory Blockchain (Legacy Simulation) ─────────────────────────────────
const blockchain = [];

require('dotenv').config();

// Safe wrapper so a bad or placeholder private key doesn't crash the server on boot
let provider;
let wallet;

try {
  // FIXED: Changed marketing site fallback to a functional public Sepolia testnet node gateway
  provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL || "https://ankr.com");
 
  const rawKey = process.env.PRIVATE_KEY;
  const isPlaceholder = !rawKey || rawKey.includes('your_test_wallet_private_key');
  
  const privateKey = !isPlaceholder ? rawKey : ethers.Wallet.createRandom().privateKey;
  wallet = new ethers.Wallet(privateKey, provider);
} catch (err) {
  logger.error(`Wallet initialization failed on boot: ${err.message}. Using safe fallback memory key.`);
  provider = null;
  wallet = ethers.Wallet.createRandom(); 
}

function calculateHash(data, previousHash, timestamp) {
  return crypto
    .createHash('sha256')
    .update(data + previousHash + timestamp)
    .digest('hex');
}

function createGenesisBlock() {
  const timestamp = new Date('2026-01-01T00:00:00Z').toISOString();
  const block = {
    index: 0,
    timestamp,
    data: 'GENESIS_BLOCK',
    previousHash: '0',
    hash: calculateHash('GENESIS_BLOCK', '0', timestamp),
  };
  blockchain.push(block);
  logger.info('Blockchain: Genesis block created');
  return block;
}

// Initialize with genesis block
createGenesisBlock();

function createBlock(data) {
  const previousBlock = blockchain[blockchain.length - 1];
  const timestamp = new Date().toISOString();
  const index = previousBlock.index + 1;
  const previousHash = previousBlock.hash;

  const hash = calculateHash(data, previousHash, timestamp);

  const newBlock = {
    index,
    timestamp,
    data,
    previousHash,
    hash,
  };

  blockchain.push(newBlock);
  logger.info(`Blockchain: Block #${index} created | Hash: ${hash.substring(0, 16)}...`);

  return newBlock;
}

function getBlockchain() {
  return [...blockchain];
}

function getLatestBlock() {
  return blockchain[blockchain.length - 1];
}

function validateChain() {
  for (let i = 1; i < blockchain.length; i++) {
    const current = blockchain[i];
    const previous = blockchain[i - 1];

    const recalculated = calculateHash(current.data, current.previousHash, current.timestamp);
    if (current.hash !== recalculated) {
      logger.warn(`Blockchain: Integrity broken at block #${current.index} – hash mismatch`);
      return { isValid: false, brokenAt: current.index };
    }

    if (current.previousHash !== previous.hash) {
      logger.warn(`Blockchain: Chain broken at block #${current.index} – previousHash mismatch`);
      return { isValid: false, brokenAt: current.index };
    }
  }

  return { isValid: true, brokenAt: null };
}

function hashFileBuffer(fileBuffer) {
  if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
    throw new Error('Invalid file buffer provided for hashing');
  }
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

function verifyPDFIntegrity(pdfBuffer, storedBlockchain) {
  if (!pdfBuffer || !storedBlockchain) {
    return {
      verified: false,
      status: 'ERROR',
      details: { reason: 'Missing PDF buffer or blockchain data' },
    };
  }

  const currentPdfHash = hashFileBuffer(pdfBuffer);

  const recalculatedBlockHash = calculateHash(
    currentPdfHash,
    storedBlockchain.previousHash,
    storedBlockchain.timestamp.toISOString()
  );

  const verified = recalculatedBlockHash === storedBlockchain.hash;

  return {
    verified,
    status: verified ? 'VERIFIED' : 'TAMPERED',
    details: {
      currentPdfHash,
      storedBlockHash: storedBlockchain.hash,
      recalculatedBlockHash,
      blockId: storedBlockchain.blockId,
      previousHash: storedBlockchain.previousHash,
      timestamp: storedBlockchain.timestamp,
    },
  };
}

// ─── LIVE WEB3 BLOCKCHAIN & IPFS ACCELERATOR (SAFE CRASH-PROOF IMPLEMENTATION) ───

let pinataInstance = null;
let contractInstance = null;
let initializationAttempted = false;

function initializeWeb3() {
  if (pinataInstance && contractInstance) {
    return { pinata: pinataInstance, contract: contractInstance };
  }

  try {
    if (!process.env.PINATA_API_KEY || !process.env.PINATA_SECRET_API_KEY) {
      throw new Error("Missing Pinata configuration keys in your environment variables (.env).");
    }
    if (!process.env.BLOCKCHAIN_RPC_URL || !process.env.PRIVATE_KEY || !process.env.CONTRACT_ADDRESS) {
      throw new Error("Missing Web3 network settings (RPC_URL, PRIVATE_KEY, or CONTRACT_ADDRESS) in your environment variables (.env).");
    }

    pinataInstance = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);
    
    const providerInstance = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);
    const walletInstance = new ethers.Wallet(process.env.PRIVATE_KEY, providerInstance);
    
    const contractABI = [
      "function storeRecord(string memory _id, string memory _cid, string memory _hash) public",
      "function getRecord(string memory _id) public view returns (string memory, string memory)"
    ];

    contractInstance = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, walletInstance);
    logger.info("Web3/IPFS Decentralized Services Engine initialized successfully.");
    
    return { pinata: pinataInstance, contract: contractInstance };
  } catch (error) {
    if (!initializationAttempted) {
      logger.error(`WEB3 MODULE DELAYED: Running without live Blockchain/IPFS connectivity. Reason: ${error.message}`);
      initializationAttempted = true;
    }
    return { pinata: null, contract: null };
  }
}

async function secureUpload(ackNumber, fileBuffer, originalName) {
  try {
    const { pinata, contract } = initializeWeb3();
    if (!pinata || !contract) {
      throw new Error("Action Aborted: Web3 infrastructure components are misconfigured or uninitialized in your .env file.");
    }

    const fileHash = hashFileBuffer(fileBuffer);
    const readableStream = stream.Readable.from(fileBuffer);
    const pinataOptions = {
      pinataMetadata: {
        name: `${ackNumber}_${originalName}`
      } 
    };    
    
    logger.info(`IPFS: Initializing decentralized file stream upload via Pinata.`);
    const pinataResult = await pinata.pinFileToIPFS(readableStream, pinataOptions);
    const ipfsCID = pinataResult.IpfsHash;
    
    logger.info(`IPFS: File successfully anchored. Content Address ID: ${ipfsCID}`);

    logger.info(`Web3: Generating transaction block payload for Ack ID: ${ackNumber}`);
    const tx = await contract.storeRecord(ackNumber, ipfsCID, fileHash);
    await tx.wait();
    logger.info(`Web3: Transaction structural processing finalized. Hash identifier: ${tx.hash}`);
    
    return { ipfsCID, fileHash };
  } catch (error) {
    logger.error("Web3/IPFS Engine failed to complete decentralized staging:", error);
    throw error;
  }
}

function getContractInstance() {
  const { contract } = initializeWeb3();
  if (!contract) {
    return {
      getRecord: async () => {
        throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
      },
      storeRecord: async () => {
        throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
      }
    };
  }
  return contract;
}

async function secureDownload(ackNumber) {
  try {
    const liveContract = getContractInstance();
    const [cid, fileHash] = await liveContract.getRecord(ackNumber);
    return { cid, fileHash };
  } catch (error) {
    logger.error(`Web3 Engine failed to query ledger information for Ack ID: ${ackNumber}`, error);
    throw error;
  }
}

module.exports = {
  createBlock,
  getBlockchain,
  getLatestBlock,
  validateChain,
  hashFileBuffer,
  verifyPDFIntegrity,
  
  secureUpload,
  secureDownload,
  get contract() {
    return getContractInstance();
  }
};


// const crypto = require('crypto');
// const pinataSDK = require('@pinata/sdk');
// const { ethers } = require('ethers');
// const stream = require('stream');
// const logger = require('./logger');

// // ─── In-Memory Blockchain (Legacy Simulation) ─────────────────────────────────
// const blockchain = [];

// require('dotenv').config();

// // Safe wrapper so a bad or placeholder private key doesn't crash the server on boot
// let provider;
// let wallet;


// try {
//   provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL || "https://ankr.com");
  
//   const rawKey = process.env.PRIVATE_KEY;
//   const isPlaceholder = !rawKey || rawKey.includes('your_test_wallet_private_key');
  
//   const privateKey = !isPlaceholder ? rawKey : ethers.Wallet.createRandom().privateKey;
//   wallet = new ethers.Wallet(privateKey, provider);
// } catch (err) {
//   logger.error(`Wallet initialization failed on boot: ${err.message}. Using safe fallback memory key.`);
//   provider = null;
//   wallet = ethers.Wallet.createRandom(); 
// }


// function calculateHash(data, previousHash, timestamp) {
//   return crypto
//     .createHash('sha256')
//     .update(data + previousHash + timestamp)
//     .digest('hex');
// }

// function createGenesisBlock() {
//   const timestamp = new Date('2026-01-01T00:00:00Z').toISOString();
//   const block = {
//     index: 0,
//     timestamp,
//     data: 'GENESIS_BLOCK',
//     previousHash: '0',
//     hash: calculateHash('GENESIS_BLOCK', '0', timestamp),
//   };
//   blockchain.push(block);
//   logger.info('Blockchain: Genesis block created');
//   return block;
// }

// // Initialize with genesis block
// createGenesisBlock();

// function createBlock(data) {
//   const previousBlock = blockchain[blockchain.length - 1];
//   const timestamp = new Date().toISOString();
//   const index = previousBlock.index + 1;
//   const previousHash = previousBlock.hash;

//   const hash = calculateHash(data, previousHash, timestamp);

//   const newBlock = {
//     index,
//     timestamp,
//     data,
//     previousHash,
//     hash,
//   };

//   blockchain.push(newBlock);
//   logger.info(`Blockchain: Block #${index} created | Hash: ${hash.substring(0, 16)}...`);

//   return newBlock;
// }

// function getBlockchain() {
//   return [...blockchain];
// }

// function getLatestBlock() {
//   return blockchain[blockchain.length - 1];
// }

// function validateChain() {
//   for (let i = 1; i < blockchain.length; i++) {
//     const current = blockchain[i];
//     const previous = blockchain[i - 1];

//     const recalculated = calculateHash(current.data, current.previousHash, current.timestamp);
//     if (current.hash !== recalculated) {
//       logger.warn(`Blockchain: Integrity broken at block #${current.index} – hash mismatch`);
//       return { isValid: false, brokenAt: current.index };
//     }

//     if (current.previousHash !== previous.hash) {
//       logger.warn(`Blockchain: Chain broken at block #${current.index} – previousHash mismatch`);
//       return { isValid: false, brokenAt: current.index };
//     }
//   }

//   return { isValid: true, brokenAt: null };
// }

// function hashFileBuffer(fileBuffer) {
//   if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
//     throw new Error('Invalid file buffer provided for hashing');
//   }
//   return crypto.createHash('sha256').update(fileBuffer).digest('hex');
// }

// function verifyPDFIntegrity(pdfBuffer, storedBlockchain) {
//   if (!pdfBuffer || !storedBlockchain) {
//     return {
//       verified: false,
//       status: 'ERROR',
//       details: { reason: 'Missing PDF buffer or blockchain data' },
//     };
//   }

//   const currentPdfHash = hashFileBuffer(pdfBuffer);

//   const recalculatedBlockHash = calculateHash(
//     currentPdfHash,
//     storedBlockchain.previousHash,
//     storedBlockchain.timestamp.toISOString()
//   );

//   const verified = recalculatedBlockHash === storedBlockchain.hash;

//   return {
//     verified,
//     status: verified ? 'VERIFIED' : 'TAMPERED',
//     details: {
//       currentPdfHash,
//       storedBlockHash: storedBlockchain.hash,
//       recalculatedBlockHash,
//       blockId: storedBlockchain.blockId,
//       previousHash: storedBlockchain.previousHash,
//       timestamp: storedBlockchain.timestamp,
//     },
//   };
// }

// // ─── LIVE WEB3 BLOCKCHAIN & IPFS ACCELERATOR (SAFE CRASH-PROOF IMPLEMENTATION) ───

// let pinataInstance = null;
// let contractInstance = null;
// let initializationAttempted = false;

// // Safe wrapper to prevent application from crashing on boot due to bad config env keys
// function initializeWeb3() {
//   if (pinataInstance && contractInstance) {
//     return { pinata: pinataInstance, contract: contractInstance };
//   }

//   try {
//     if (!process.env.PINATA_API_KEY || !process.env.PINATA_SECRET_API_KEY) {
//       throw new Error("Missing Pinata configuration keys in your environment variables (.env).");
//     }
//     if (!process.env.BLOCKCHAIN_RPC_URL || !process.env.PRIVATE_KEY || !process.env.CONTRACT_ADDRESS) {
//       throw new Error("Missing Web3 network settings (RPC_URL, PRIVATE_KEY, or CONTRACT_ADDRESS) in your environment variables (.env).");
//     }

//     // Initialize Pinata SDK safely
//     pinataInstance = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);
    
//     // Initialize Ethers provider network components
//     const providerInstance = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);
//     const walletInstance = new ethers.Wallet(process.env.PRIVATE_KEY, providerInstance);
    
//     const contractABI = [
//       "function storeRecord(string memory _id, string memory _cid, string memory _hash) public",
//       "function getRecord(string memory _id) public view returns (string memory, string memory)"
//     ];

//     contractInstance = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, walletInstance);
//     logger.info("Web3/IPFS Decentralized Services Engine initialized successfully.");
    
//     return { pinata: pinataInstance, contract: contractInstance };
//   } catch (error) {
//     // Log the configuration warning only once during startup to keep logs clean
//     if (!initializationAttempted) {
//       logger.error(`WEB3 MODULE DELAYED: Running without live Blockchain/IPFS connectivity. Reason: ${error.message}`);
//       initializationAttempted = true;
//     }
//     return { pinata: null, contract: null };
//   }
// }
// // ─── In-Memory Blockchain (Legacy Simulation) ─────────────────────────────────
// const blockchain = [];

// require('dotenv').config();

// // FIX: Wrap inside a try/catch block so a bad or missing private key doesn't crash the server on boot
// let provider;
// let wallet;

// try {
//   provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL || "https://ankr.com");
  
//   // Clean up private key check to avoid processing placeholder text
//   const rawKey = process.env.PRIVATE_KEY;
//   const isPlaceholder = !rawKey || rawKey.includes('your_test_wallet_private_key');
  
//   const privateKey = !isPlaceholder ? rawKey : ethers.Wallet.createRandom().privateKey;
//   wallet = new ethers.Wallet(privateKey, provider);
// } catch (err) {
//   logger.error(`Wallet initialization failed on boot: ${err.message}. Using safe fallback memory key.`);
//   // Complete fallback to keep the process running
//   provider = null;
//   wallet = ethers.Wallet.createRandom(); 
// }




// /**
//  * Handles calculating structural cryptographic fingerprints, uploading raw metrics
//  * to Pinata IPFS gateways, and executing structural ledger entry anchors on-chain.
//  */
// async function secureUpload(ackNumber, fileBuffer, originalName) {
//   try {
//     const { pinata, contract } = initializeWeb3();
//     if (!pinata || !contract) {
//       throw new Error("Action Aborted: Web3 infrastructure components are misconfigured or uninitialized in your .env file.");
//     }

//     const fileHash = hashFileBuffer(fileBuffer);
//     const readableStream = stream.Readable.from(fileBuffer);
//     const pinataOptions = {
//       pinataMetadata: {
//         name: `${ackNumber}_${originalName}`
//       } 
//     };    
    
//     logger.info(`IPFS: Initializing decentralized file stream upload via Pinata.`);
//     const pinataResult = await pinata.pinFileToIPFS(readableStream, pinataOptions);
//     const ipfsCID = pinataResult.IpfsHash;
    
//     logger.info(`IPFS: File successfully anchored. Content Address ID: ${ipfsCID}`);

//     logger.info(`Web3: Generating transaction block payload for Ack ID: ${ackNumber}`);
//     const tx = await contract.storeRecord(ackNumber, ipfsCID, fileHash);
//     await tx.wait();
//     logger.info(`Web3: Transaction structural processing finalized. Hash identifier: ${tx.hash}`);
    
//     return { ipfsCID, fileHash };
//   } catch (error) {
//     logger.error("Web3/IPFS Engine failed to complete decentralized staging:", error);
//     throw error;
//   }
// }

// function getContractInstance() {
//   const { contract } = initializeWeb3();
//   if (!contract) {
//     return {
//       getRecord: async () => {
//         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
//       },
//       storeRecord: async () => {
//         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
//       }
//     };
//   }
//   return contract;
// }

// /**
//  * Reads expected ledger integrity records directly from the live blockchain contract [1]
//  */
// async function secureDownload(ackNumber) {
//   try {
//     const liveContract = getContractInstance();
//     const [cid, fileHash] = await liveContract.getRecord(ackNumber);
//     return { cid, fileHash };
//   } catch (error) {
//     logger.error(`Web3 Engine failed to query ledger information for Ack ID: ${ackNumber}`, error);
//     throw error;
//   }
// }

// module.exports = {
//   // Legacy simulation tools
//   createBlock,
//   getBlockchain,
//   getLatestBlock,
//   validateChain,
//   hashFileBuffer,
//   verifyPDFIntegrity,
  
//   // New production Web3 capabilities
//   secureUpload,
//   secureDownload,
//   get contract() {
//     return getContractInstance();
//   }
// };



// // // utils/blockchain.js
// // // Simulated Blockchain Integrity System & Real Decentralized IPFS Storage Engine
// // // Handles both legacy in-memory chain validation and live Web3 on-chain storage safely.

// // const crypto = require('crypto');
// // const pinataSDK = require('@pinata/sdk');
// // const { ethers } = require('ethers');
// // const stream = require('stream');
// // const logger = require('./logger');

// // // ─── In-Memory Blockchain (Legacy Simulation) ─────────────────────────────────
// // const blockchain = [];


// // require('dotenv').config();

// // const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);

// // // EASIER WAY: If no private key is found, automatically generate a random test wallet!
// // const privateKey = process.env.PRIVATE_KEY && process.env.PRIVATE_KEY !== 'your_test_wallet_private_key_...'
// //     ? process.env.PRIVATE_KEY 
// //     : ethers.Wallet.createRandom().privateKey; 

// // const wallet = new ethers.Wallet(privateKey, provider);

// // function calculateHash(data, previousHash, timestamp) {
// //   return crypto
// //     .createHash('sha256')
// //     .update(data + previousHash + timestamp)
// //     .digest('hex');
// // }

// // function createGenesisBlock() {
// //   const timestamp = new Date('2026-01-01T00:00:00Z').toISOString();
// //   const block = {
// //     index: 0,
// //     timestamp,
// //     data: 'GENESIS_BLOCK',
// //     previousHash: '0',
// //     hash: calculateHash('GENESIS_BLOCK', '0', timestamp),
// //   };
// //   blockchain.push(block);
// //   logger.info('Blockchain: Genesis block created');
// //   return block;
// // }
// // createGenesisBlock();

// // function createBlock(data) {
// //   const previousBlock = blockchain[blockchain.length - 1];
// //   const timestamp = new Date().toISOString();
// //   const index = previousBlock.index + 1;
// //   const previousHash = previousBlock.hash;

// //   const hash = calculateHash(data, previousHash, timestamp);

// //   const newBlock = {
// //     index,
// //     timestamp,
// //     data,
// //     previousHash,
// //     hash,
// //   };

// //   blockchain.push(newBlock);
// //   logger.info(`Blockchain: Block #${index} created | Hash: ${hash.substring(0, 16)}...`);

// //   return newBlock;
// // }

// // function getBlockchain() {
// //   return [...blockchain];
// // }

// // function getLatestBlock() {
// //   return blockchain[blockchain.length - 1];
// // }

// // function validateChain() {
// //   for (let i = 1; i < blockchain.length; i++) {
// //     const current = blockchain[i];
// //     const previous = blockchain[i - 1];

// //     const recalculated = calculateHash(current.data, current.previousHash, current.timestamp);
// //     if (current.hash !== recalculated) {
// //       logger.warn(`Blockchain: Integrity broken at block #${current.index} – hash mismatch`);
// //       return { isValid: false, brokenAt: current.index };
// //     }

// //     if (current.previousHash !== previous.hash) {
// //       logger.warn(`Blockchain: Chain broken at block #${current.index} – previousHash mismatch`);
// //       return { isValid: false, brokenAt: current.index };
// //     }
// //   }

// //   return { isValid: true, brokenAt: null };
// // }

// // function hashFileBuffer(fileBuffer) {
// //   if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
// //     throw new Error('Invalid file buffer provided for hashing');
// //   }
// //   return crypto.createHash('sha256').update(fileBuffer).digest('hex');
// // }

// // function verifyPDFIntegrity(pdfBuffer, storedBlockchain) {
// //   if (!pdfBuffer || !storedBlockchain) {
// //     return {
// //       verified: false,
// //       status: 'ERROR',
// //       details: { reason: 'Missing PDF buffer or blockchain data' },
// //     };
// //   }

// //   const currentPdfHash = hashFileBuffer(pdfBuffer);

// //   const recalculatedBlockHash = calculateHash(
// //     currentPdfHash,
// //     storedBlockchain.previousHash,
// //     storedBlockchain.timestamp.toISOString()
// //   );

// //   const verified = recalculatedBlockHash === storedBlockchain.hash;

// //   return {
// //     verified,
// //     status: verified ? 'VERIFIED' : 'TAMPERED',
// //     details: {
// //       currentPdfHash,
// //       storedBlockHash: storedBlockchain.hash,
// //       recalculatedBlockHash,
// //       blockId: storedBlockchain.blockId,
// //       previousHash: storedBlockchain.previousHash,
// //       timestamp: storedBlockchain.timestamp,
// //     },
// //   };
// // }


// // let pinataInstance = null;
// // let contractInstance = null;
// // let initializationAttempted = false;

// // function initializeWeb3() {
// //   if (pinataInstance && contractInstance) {
// //     return { pinata: pinataInstance, contract: contractInstance };
// //   }

// //   try {
// //     if (!process.env.PINATA_API_KEY || !process.env.PINATA_SECRET_API_KEY) {
// //       throw new Error("Missing Pinata configuration keys in your environment variables (.env).");
// //     }
// //     if (!process.env.BLOCKCHAIN_RPC_URL || !process.env.PRIVATE_KEY || !process.env.CONTRACT_ADDRESS) {
// //       throw new Error("Missing Web3 network settings (RPC_URL, PRIVATE_KEY, or CONTRACT_ADDRESS) in your environment variables (.env).");
// //     }

// //     // Initialize Pinata SDK safely
// //     pinataInstance = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

// //     // Initialize Ethers provider network components
// //     const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);
// //     const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// //     const contractABI = [
// //       "function storeRecord(string memory _id, string memory _cid, string memory _hash) public",
// //       "function getRecord(string memory _id) public view returns (string memory, string memory)"
// //     ];

// //     contractInstance = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, wallet);
// //     logger.info("Web3/IPFS Decentralized Services Engine initialized successfully.");
    
// //     return { pinata: pinataInstance, contract: contractInstance };
// //   } catch (error) {
// //     // Log the configuration warning only once during startup to keep logs clean
// //     if (!initializationAttempted) {
// //       logger.error(`WEB3 MODULE DELAYED: Running without live Blockchain/IPFS connectivity. Reason: ${error.message}`);
// //       initializationAttempted = true;
// //     }
// //     return { pinata: null, contract: null };
// //   }
// // }

// // /**
// //  * Handles calculating structural cryptographic fingerprints, uploading raw metrics
// //  * to Pinata IPFS gateways, and executing structural ledger entry anchors on-chain.
// //  */
// // async function secureUpload(ackNumber, fileBuffer, originalName) {
// //   try {
// //     const { pinata, contract } = initializeWeb3();
// //     if (!pinata || !contract) {
// //       throw new Error("Action Aborted: Web3 infrastructure components are misconfigured or uninitialized in your .env file.");
// //     }

// //     const fileHash = hashFileBuffer(fileBuffer);
// //     const readableStream = stream.Readable.from(fileBuffer);
// //     const pinataOptions = {
// //       pinataMetadata: {
// //         name: `${ackNumber}_${originalName}`
// //       }
// //     };

// //     logger.info(`IPFS: Initializing decentralized file stream upload via Pinata.`);
// //     const pinataResult = await pinata.pinFileToIPFS(readableStream, pinataOptions);
// //     const ipfsCID = pinataResult.IpfsHash;
    
// //     logger.info(`IPFS: File successfully anchored. Content Address ID: ${ipfsCID}`);

// //     logger.info(`Web3: Generating transaction block payload for Ack ID: ${ackNumber}`);
// //     const tx = await contract.storeRecord(ackNumber, ipfsCID, fileHash);
    
// //     await tx.wait();
// //     logger.info(`Web3: Transaction structural processing finalized. Hash identifier: ${tx.hash}`);

// //     return { ipfsCID, fileHash };
// //   } catch (error) {
// //     logger.error("Web3/IPFS Engine failed to complete decentralized staging:", error);
// //     throw error;
// //   }
// // }



// // function getContractInstance() {
// //   const { contract } = initializeWeb3();
// //   if (!contract) {
// //     return {
// //       getRecord: async () => {
// //         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
// //       },
// //       storeRecord: async () => {
// //         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
// //       }
// //     };
// //   }
// //   return contract;
// // }

// // module.exports = {
// //   createBlock,
// //   getBlockchain,
// //   getLatestBlock,
// //   validateChain,
// //   hashFileBuffer,
// //   verifyPDFIntegrity,

// //   secureUpload,
// //   get contract() {
// //     return getContractInstance();
// //   }
// // };

// // // Fixed function that NEVER throws an error when called during 'require' layout setup
// // // function getSafeContract() {
// // //   const { contract } = initializeWeb3();
  
// // //   // If the contract is not available yet, we return a mock object with a getRecord function.
// // //   // When controllers try to use it later, it will throw the error safely inside the route execution loop.
// // //   if (!contract) {
// // //     return {
// // //       getRecord: async () => {
// // //         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
// // //       },
// // //       storeRecord: async () => {
// // //         throw new Error("Blockchain operation failed: Web3 engine is uninitialized. Check your .env variables.");
// // //       }
// // //     };
// // //   }
// // //   return contract;
// // // }

// // module.exports = {
// //   // Legacy simulation tools
// //   createBlock,
// //   getBlockchain,
// //   getLatestBlock,
// //   validateChain,
// //   hashFileBuffer,
// //   verifyPDFIntegrity,
  
// //   // New production Web3 capabilities
// //   secureUpload,
// //   get contract() {
// //     return getSafeContract();
// //   }
// // };





// // // utils/blockchain.js
// // // Simulated Blockchain Integrity System & Real Decentralized IPFS Storage Engine
// // // Handles both legacy in-memory chain validation and live Web3 on-chain storage safely.

// // // const crypto = require('crypto');
// // // const pinataSDK = require('@pinata/sdk');
// // // const { ethers } = require('ethers');
// // // const stream = require('stream');
// // // const logger = require('./logger');

// // // // ─── In-Memory Blockchain (Legacy Simulation) ─────────────────────────────────
// // // const blockchain = [];

// // // function calculateHash(data, previousHash, timestamp) {
// // //   return crypto
// // //     .createHash('sha256')
// // //     .update(data + previousHash + timestamp)
// // //     .digest('hex');
// // // }

// // // function createGenesisBlock() {
// // //   const timestamp = new Date('2026-01-01T00:00:00Z').toISOString();
// // //   const block = {
// // //     index: 0,
// // //     timestamp,
// // //     data: 'GENESIS_BLOCK',
// // //     previousHash: '0',
// // //     hash: calculateHash('GENESIS_BLOCK', '0', timestamp),
// // //   };
// // //   blockchain.push(block);
// // //   logger.info('Blockchain: Genesis block created');
// // //   return block;
// // // }

// // // // Initialize with genesis block
// // // createGenesisBlock();

// // // function createBlock(data) {
// // //   const previousBlock = blockchain[blockchain.length - 1];
// // //   const timestamp = new Date().toISOString();
// // //   const index = previousBlock.index + 1;
// // //   const previousHash = previousBlock.hash;

// // //   const hash = calculateHash(data, previousHash, timestamp);

// // //   const newBlock = {
// // //     index,
// // //     timestamp,
// // //     data,
// // //     previousHash,
// // //     hash,
// // //   };

// // //   blockchain.push(newBlock);
// // //   logger.info(`Blockchain: Block #${index} created | Hash: ${hash.substring(0, 16)}...`);

// // //   return newBlock;
// // // }

// // // function getBlockchain() {
// // //   return [...blockchain];
// // // }

// // // function getLatestBlock() {
// // //   return blockchain[blockchain.length - 1];
// // // }

// // // function validateChain() {
// // //   for (let i = 1; i < blockchain.length; i++) {
// // //     const current = blockchain[i];
// // //     const previous = blockchain[i - 1];

// // //     const recalculated = calculateHash(current.data, current.previousHash, current.timestamp);
// // //     if (current.hash !== recalculated) {
// // //       logger.warn(`Blockchain: Integrity broken at block #${current.index} – hash mismatch`);
// // //       return { isValid: false, brokenAt: current.index };
// // //     }

// // //     if (current.previousHash !== previous.hash) {
// // //       logger.warn(`Blockchain: Chain broken at block #${current.index} – previousHash mismatch`);
// // //       return { isValid: false, brokenAt: current.index };
// // //     }
// // //   }

// // //   return { isValid: true, brokenAt: null };
// // // }

// // // function hashFileBuffer(fileBuffer) {
// // //   if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
// // //     throw new Error('Invalid file buffer provided for hashing');
// // //   }
// // //   return crypto.createHash('sha256').update(fileBuffer).digest('hex');
// // // }

// // // function verifyPDFIntegrity(pdfBuffer, storedBlockchain) {
// // //   if (!pdfBuffer || !storedBlockchain) {
// // //     return {
// // //       verified: false,
// // //       status: 'ERROR',
// // //       details: { reason: 'Missing PDF buffer or blockchain data' },
// // //     };
// // //   }

// // //   const currentPdfHash = hashFileBuffer(pdfBuffer);

// // //   const recalculatedBlockHash = calculateHash(
// // //     currentPdfHash,
// // //     storedBlockchain.previousHash,
// // //     storedBlockchain.timestamp.toISOString()
// // //   );

// // //   const verified = recalculatedBlockHash === storedBlockchain.hash;

// // //   return {
// // //     verified,
// // //     status: verified ? 'VERIFIED' : 'TAMPERED',
// // //     details: {
// // //       currentPdfHash,
// // //       storedBlockHash: storedBlockchain.hash,
// // //       recalculatedBlockHash,
// // //       blockId: storedBlockchain.blockId,
// // //       previousHash: storedBlockchain.previousHash,
// // //       timestamp: storedBlockchain.timestamp,
// // //     },
// // //   };
// // // }

// // // // ─── LIVE WEB3 BLOCKCHAIN & IPFS ACCELERATOR (SAFE SHIELDED IMPLEMENTATION) ───

// // // let pinata = null;
// // // let contract = null;

// // // // This function safely builds your web3 connections only when needed, preventing startup crashes.
// // // function initializeWeb3() {
// // //   if (pinata && contract) return { pinata, contract }; // Already initialized

// // //   try {
// // //     if (!process.env.PINATA_API_KEY || !process.env.PINATA_SECRET_API_KEY) {
// // //       throw new Error("Missing PINATA_API_KEY or PINATA_SECRET_API_KEY in your .env file.");
// // //     }
// // //     if (!process.env.BLOCKCHAIN_RPC_URL || !process.env.PRIVATE_KEY || !process.env.CONTRACT_ADDRESS) {
// // //       throw new Error("Missing Web3 configuration (BLOCKCHAIN_RPC_URL, PRIVATE_KEY, or CONTRACT_ADDRESS) in your .env file.");
// // //     }

// // //     // 1. Authenticate with Pinata IPFS Service
// // //     pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);

// // //     // 2. Build live JSON RPC Provider network connection
// // //     const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);
    
// // //     // 3. Instantiate Wallet Signer
// // //     const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// // //     // 4. Define Smart Contract Methods ABI
// // //     const contractABI = [
// // //       "function storeRecord(string memory _id, string memory _cid, string memory _hash) public",
// // //       "function getRecord(string memory _id) public view returns (string memory, string memory)"
// // //     ];

// // //     // 5. Connect to live operational smart contract instances
// // //     contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, wallet);
    
// // //     logger.info("Web3/IPFS Engine initialized successfully.");
// // //     return { pinata, contract };

// // //   } catch (error) {
// // //     logger.error(`CRITICAL WEB3 CONFIG ERROR: ${error.message}`);
// // //     // We log the error clearly instead of letting the entire Node app crash
// // //     return { pinata: null, contract: null };
// // //   }
// // // }

// // /**
// //  * Handles calculating structural cryptographic fingerprints, uploading raw metrics
// //  * to Pinata IPFS gateways, and executing structural ledger entry anchors on-chain.
// //  */
// // async function secureUpload(ackNumber, fileBuffer, originalName) {
// //   try {
// //     const { pinata: activePinata, contract: activeContract } = initializeWeb3();
// //     if (!activePinata || !activeContract) {
// //       throw new Error("Cannot upload: Web3 components were not configured correctly in .env.");
// //     }

// //     // Generate real SHA-256 string footprint verification
// //     const fileHash = hashFileBuffer(fileBuffer);

// //     // Turn buffer data streams into memory channels for Pinata ingestion layers
// //     const readableStream = stream.Readable.from(fileBuffer);
// //     const pinataOptions = {
// //       pinataMetadata: {
// //         name: `${ackNumber}_${originalName}`
// //       }
// //     };

// //     logger.info(`IPFS: Initializing decentralized file stream upload via Pinata.`);
// //     const pinataResult = await activePinata.pinFileToIPFS(readableStream, pinataOptions);
// //     const ipfsCID = pinataResult.IpfsHash;
    
// //     logger.info(`IPFS: File successfully anchored. Content Address ID: ${ipfsCID}`);

// //     // Call live smart contract methods to bind tracking markers permanently on-chain
// //     logger.info(`Web3: Generating transaction block payload for Ack ID: ${ackNumber}`);
// //     const tx = await activeContract.storeRecord(ackNumber, ipfsCID, fileHash);
    
// //     // Hold operational execution context blocks until on-chain verification completes
// //     await tx.wait();
// //     logger.info(`Web3: Transaction structural processing finalized. Hash identifier: ${tx.hash}`);

// //     return { ipfsCID, fileHash };
// //   } catch (error) {
// //     logger.error("Web3/IPFS Engine failed to complete decentralized staging:", error);
// //     throw error;
// //   }
// // }

// // // Export a proxy function for contract reading to ensure it initializes safely too
// // function getContractInstance() {
// //   const { contract: activeContract } = initializeWeb3();
// //   if (!activeContract) {
// //     throw new Error("Web3 Contract instance is unavailable due to configuration errors.");
// //   }
// //   return activeContract;
// // }

// // module.exports = {
// //   // Legacy simulation tools
// //   createBlock,
// //   getBlockchain,
// //   getLatestBlock,
// //   validateChain,
// //   hashFileBuffer,
// //   verifyPDFIntegrity,
  
// //   // New production Web3 capabilities
// //   secureUpload,
// //   // Using a getter function prevents route handlers from calling properties on 'null' on startup
// //   get contract() {
// //     return getContractInstance();
// //   }
// // };



















// // utils/blockchain.js
// // Simulated Blockchain Integrity System
// // Maintains an in-memory chain of SHA-256-linked blocks for tamper-proof PDF verification

// // const crypto = require('crypto');
// // const logger = require('./logger');

// // // ─── In-Memory Blockchain ────────────────────────────────────────────────────
// // // The chain is initialized with a genesis block.
// // // Each new block links to the previous one via previousHash,
// // // making any retroactive modification detectable.

// // const blockchain = [];

// // // ─── Utility: Calculate SHA-256 ──────────────────────────────────────────────
// // function calculateHash(data, previousHash, timestamp) {
// //   return crypto
// //     .createHash('sha256')
// //     .update(data + previousHash + timestamp)
// //     .digest('hex');
// // }

// // // ─── Create Genesis Block ────────────────────────────────────────────────────
// // function createGenesisBlock() {
// //   const timestamp = new Date('2026-01-01T00:00:00Z').toISOString();
// //   const block = {
// //     index: 0,
// //     timestamp,
// //     data: 'GENESIS_BLOCK',
// //     previousHash: '0',
// //     hash: calculateHash('GENESIS_BLOCK', '0', timestamp),
// //   };
// //   blockchain.push(block);
// //   logger.info('Blockchain: Genesis block created');
// //   return block;
// // }

// // // Initialize with genesis block
// // createGenesisBlock();

// // // ─── Create a New Block ──────────────────────────────────────────────────────
// // /**
// //  * Creates a new block and appends it to the in-memory blockchain.
// //  * @param {string} data - Usually the SHA-256 hash of a PDF file
// //  * @returns {object} The newly created block
// //  */
// // function createBlock(data) {
// //   const previousBlock = blockchain[blockchain.length - 1];
// //   const timestamp = new Date().toISOString();
// //   const index = previousBlock.index + 1;
// //   const previousHash = previousBlock.hash;

// //   const hash = calculateHash(data, previousHash, timestamp);

// //   const newBlock = {
// //     index,
// //     timestamp,
// //     data,
// //     previousHash,
// //     hash,
// //   };

// //   blockchain.push(newBlock);
// //   logger.info(`Blockchain: Block #${index} created | Hash: ${hash.substring(0, 16)}...`);

// //   return newBlock;
// // }

// // // ─── Get the Full Blockchain (for internal use only) ──────────────────────────
// // /**
// //  * Returns a shallow copy of the blockchain array.
// //  * NOTE: Never expose this publicly – admin/internal use only.
// //  * @returns {Array} Copy of all blocks
// //  */
// // function getBlockchain() {
// //   return [...blockchain];
// // }

// // // ─── Get Latest Block ─────────────────────────────────────────────────────────
// // /**
// //  * Returns the latest block in the chain
// //  * @returns {object} The most recent block
// //  */
// // function getLatestBlock() {
// //   return blockchain[blockchain.length - 1];
// // }

// // // ─── Validate Chain Integrity ─────────────────────────────────────────────────
// // /**
// //  * Validates the entire in-memory chain for integrity.
// //  * Checks that each block's hash matches recalculation and
// //  * that previousHash links are unbroken.
// //  * @returns {object} { isValid: boolean, brokenAt: number|null }
// //  */
// // function validateChain() {
// //   for (let i = 1; i < blockchain.length; i++) {
// //     const current = blockchain[i];
// //     const previous = blockchain[i - 1];

// //     // Recalculate and verify current block's hash
// //     const recalculated = calculateHash(current.data, current.previousHash, current.timestamp);
// //     if (current.hash !== recalculated) {
// //       logger.warn(`Blockchain: Integrity broken at block #${current.index} – hash mismatch`);
// //       return { isValid: false, brokenAt: current.index };
// //     }

// //     // Verify chain link
// //     if (current.previousHash !== previous.hash) {
// //       logger.warn(`Blockchain: Chain broken at block #${current.index} – previousHash mismatch`);
// //       return { isValid: false, brokenAt: current.index };
// //     }
// //   }

// //   return { isValid: true, brokenAt: null };
// // }

// // // ─── Hash a File Buffer ──────────────────────────────────────────────────────
// // /**
// //  * Generates SHA-256 hash of a file buffer (e.g., PDF)
// //  * @param {Buffer} fileBuffer - The file content as a Buffer
// //  * @returns {string} Hex-encoded SHA-256 hash
// //  */
// // function hashFileBuffer(fileBuffer) {
// //   if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
// //     throw new Error('Invalid file buffer provided for hashing');
// //   }
// //   return crypto.createHash('sha256').update(fileBuffer).digest('hex');
// // }

// // // ─── Verify a PDF Against Stored Blockchain Data ──────────────────────────────
// // /**
// //  * Verifies a PDF buffer's integrity against stored blockchain metadata.
// //  * Recalculates the hash of the PDF and compares with the stored block hash data.
// //  * @param {Buffer} pdfBuffer - The PDF file buffer to verify
// //  * @param {object} storedBlockchain - The blockchain metadata from the DB
// //  * @returns {object} { verified: boolean, details: object }
// //  */
// // function verifyPDFIntegrity(pdfBuffer, storedBlockchain) {
// //   if (!pdfBuffer || !storedBlockchain) {
// //     return {
// //       verified: false,
// //       status: 'ERROR',
// //       details: { reason: 'Missing PDF buffer or blockchain data' },
// //     };
// //   }

// //   const currentPdfHash = hashFileBuffer(pdfBuffer);

// //   // Recalculate what the block hash should be
// //   const recalculatedBlockHash = calculateHash(
// //     currentPdfHash,
// //     storedBlockchain.previousHash,
// //     storedBlockchain.timestamp.toISOString()
// //   );

// //   const verified = recalculatedBlockHash === storedBlockchain.hash;

// //   return {
// //     verified,
// //     status: verified ? 'VERIFIED' : 'TAMPERED',
// //     details: {
// //       currentPdfHash,
// //       storedBlockHash: storedBlockchain.hash,
// //       recalculatedBlockHash,
// //       blockId: storedBlockchain.blockId,
// //       previousHash: storedBlockchain.previousHash,
// //       timestamp: storedBlockchain.timestamp,
// //     },
// //   };
// // }

// // module.exports = {
// //   createBlock,
// //   getBlockchain,
// //   getLatestBlock,
// //   validateChain,
// //   hashFileBuffer,
// //   verifyPDFIntegrity,
// // };
