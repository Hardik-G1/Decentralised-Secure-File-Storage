const { ethers } = require("hardhat");

describe("FileRegistry Gas Evaluation", function () {
    let fileRegistry, owner, user1;
    
    // We will reuse these variables throughout the tests
    let sharedFileId;
    let paidFileId;
    const indexName = "shared";
    const integrityHash = ethers.id("test_integrity_hash");
    const umbralPubKey = "0x" + "ab".repeat(32);
    const keyCID = "Qm" + "a".repeat(44);
    const encryptedKey = "0x" + "cd".repeat(100);

    before(async function () {
        [owner, user1] = await ethers.getSigners();
        const FileRegistry = await ethers.getContractFactory("FileRegistry");
        fileRegistry = await FileRegistry.deploy();
        await fileRegistry.waitForDeployment();
    });


    it("Gas Cost: setMyUmbralPublicKey (First Time User)", async function () {
        // This also sets the registration blocks
        await fileRegistry.connect(owner).setMyUmbralPublicKey(umbralPubKey);
    });

    it("Gas Cost: registerFile (SHARED)", async function () {
        const tx = await fileRegistry.connect(owner).registerFile("Qm...", 0, true, 2, false, "txt");
        const receipt = await tx.wait();
        // Extract fileId from the event for later use
        sharedFileId = receipt.logs.find(e => e.eventName === 'FileRegistered').args.fileId;
    });

    it("Gas Cost: registerFile (PAID)", async function () {
        const price = ethers.parseEther("0.1");
        const tx = await fileRegistry.connect(owner).registerFile("Qm...", price, true, 3, false, "mov");
        const receipt = await tx.wait();
        paidFileId = receipt.logs.find(e => e.eventName === 'FileRegistered').args.fileId;
    });

    it("Gas Cost: setEncryptedFileKey", async function () {
        await fileRegistry.connect(owner).setEncryptedFileKey(sharedFileId, encryptedKey);
    });

    it("Gas Cost: setMasterIndex", async function () {
        const indexFileId = 1; // Assuming an index file was registered
        await fileRegistry.connect(owner).setMasterIndex(indexName, indexFileId, integrityHash);
    });

    // --- FILE ACCESS LIFECYCLE ---

    it("Gas Cost: requestAccess", async function () {
        await fileRegistry.connect(user1).requestAccess(sharedFileId);
    });

    it("Gas Cost: approveAccessRequest", async function () {
        await fileRegistry.connect(owner).approveAccessRequest(sharedFileId, user1.address);
    });

    it("Gas Cost: putKeyForOtherUser", async function () {
        await fileRegistry.connect(owner).putKeyForOtherUser(sharedFileId, user1.address, keyCID);
    });
    
    it("Gas Cost: denyAccessRequest", async function () {
        // We need a new request to deny
        const tx = await fileRegistry.connect(owner).registerFile("Qm...", 0, true, 2, false, "zip");
        const receipt = await tx.wait();
        const newFileId = receipt.logs.find(e => e.eventName === 'FileRegistered').args.fileId;
        
        await fileRegistry.connect(user1).requestAccess(newFileId);
        await fileRegistry.connect(owner).denyAccessRequest(newFileId, user1.address);
    });

    
    it("Gas Cost: requestIndexAccess", async function () {
        await fileRegistry.connect(user1).requestIndexAccess(owner.address, indexName);
    });

    it("Gas Cost: approveIndexAccessRequest", async function () {
        await fileRegistry.connect(owner).approveIndexAccessRequest(indexName, user1.address);
    });

    it("Gas Cost: grantIndexAccess", async function () {
        await fileRegistry.connect(owner).grantIndexAccess(indexName, user1.address, keyCID);
    });

    it("Gas Cost: denyIndexAccessRequest", async function () {
        // We need a new request to deny
        await fileRegistry.connect(user1).requestIndexAccess(owner.address, "paid");
        await fileRegistry.connect(owner).denyIndexAccessRequest("paid", user1.address);
    });


    it("Gas Cost: purchaseFile", async function () {
        const price = ethers.parseEther("0.1");
        await fileRegistry.connect(user1).purchaseFile(paidFileId, { value: price });
    });

    it("Gas Cost: removeFile", async function () {
        await fileRegistry.connect(owner).removeFile(sharedFileId);
    });
    
    it("Gas Cost: updateUserFileLastBlock", async function () {
        const blockNum = await ethers.provider.getBlockNumber();
        await fileRegistry.connect(owner).updateUserFileLastBlock(blockNum);
    });
    
    it("Gas Cost: updateUserIndexLastBlock", async function () {
        const blockNum = await ethers.provider.getBlockNumber();
        await fileRegistry.connect(owner).updateUserIndexLastBlock(blockNum);
    });
});