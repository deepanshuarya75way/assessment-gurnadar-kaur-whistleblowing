const pinataSDK = require('@pinata/sdk');
const { ethers } = require('ethers');
const crypto = require('crypto');
const stream = require('stream');

const pinata = new pinataSDK(process.env.PINATA_API_KEY, process.env.PINATA_SECRET_API_KEY);
const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

const contractABI = [
    "function storeRecord(string memory _id, string memory _cid, string memory _hash) public",
    "function getRecord(string memory _id) public view returns (string memory, string memory)"
];
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, wallet);

async function secureUpload(incidentId, fileBuffer, originalName) {
    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const readableStream = stream.Readable.from(fileBuffer);
    
    const pinataResult = await pinata.pinFileToIPFS(readableStream, {
        pinataMetadata: { name: originalName }
    });
    const ipfsCID = pinataResult.IpfsHash;

    const tx = await contract.storeRecord(incidentId, ipfsCID, fileHash);
    await tx.wait(); 

    return { ipfsCID, fileHash };
}

module.exports = { secureUpload, contract };
