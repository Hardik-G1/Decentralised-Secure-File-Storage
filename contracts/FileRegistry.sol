// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title FileRegistry
 * @author [Hardik/Decentralised File Storage]
 * @notice The smart contract for the Decentralised Secure File Storage application.
 * It manages file registration, ownership, access control, and index pointers with robust logic.
 */
contract FileRegistry {

    enum AccessMode { PUBLIC, PRIVATE, SHARED, PAID }

    struct File {
        address payable owner;
        string ipfsCID;
        uint256 price;
        bool isEncrypted;
        AccessMode mode;
        bool isIndex;
        bool isDeleted;
        string fileExtension;
    }

    struct IndexPointer {
        uint256 fileId;
        bytes32 integrityHash; 
    }


    uint256 private _fileIdCounter;
    mapping(address => uint256) public userFileAccessUpdateBlock;
    mapping(address => uint256) public userIndexAccessUpdateBlock;
    mapping(uint256 => File) public files;

    mapping(address => mapping(string => IndexPointer)) public masterIndexPointers;

    mapping(uint256 => mapping(address => bool)) public accessRights;

    mapping(uint256 => mapping(address => bool)) public accessRequests;
    mapping(address => mapping(string => mapping(address => bool))) public indexAccessRequests;

    mapping(uint256 => bytes) private encryptedFileKeys;

    mapping(uint256 => mapping(address => string)) public grantedKeyLocations;
    mapping(address => bytes) public userUmbralPublicKeys;
    mapping(address => bytes32) public encryptedUmbralKeyHashes;
    mapping(address => mapping(string => mapping(address => string))) public indexAccessKeyLocations;


    modifier fileExists(uint256 _fileId) {
        require(files[_fileId].owner != address(0), "FileRegistry: File does not exist.");
        _;
    }

    modifier notDeleted(uint256 _fileId) {
        require(!files[_fileId].isDeleted, "File has been deleted.");
        _;
    }

    modifier onlyFileOwner(uint256 _fileId) {
        require(files[_fileId].owner == msg.sender, "FileRegistry: Caller is not the file owner.");
        _;
    }

    event FileRegistered(uint256 indexed fileId, address indexed owner, string fileExtension);
    event FileRemoved(uint256 indexed fileId);
    event MasterIndexSet(address indexed owner, string indexName, uint256 fileId);

    event AccessRequestDenied(uint256 indexed fileId, address indexed requester, address owner); 
    event AccessGranted(uint256 indexed fileId, address indexed requester , address owner);
    event AccessRequested(uint256 indexed fileId, address indexed requester, address owner);

    event IndexAccessGranted(address indexed owner, string indexName, address user, string keyLocationCID);
    event IndexAccessRequested(address indexed owner, string indexName, address requester);
    event IndexAccessRequestApproved(address indexed owner, string indexName, address requester);
    event IndexAccessRequestDenied(address indexed owner, string indexName, address requester);

    event KeyForUserPublished(uint256 indexed fileId, address indexed user, string keyLocationCID);
    event FilePurchased(uint256 indexed fileId, address buyer, uint256 price);
    event UmbralKeySet(address indexed owner, bytes32 ipfsHash);
    event UmbralPublicKeySet(address indexed owner);

    /**
     * @notice Registers a new file (content or index file) and returns its unique ID.
     */
    function registerFile(
        string memory _ipfsCID,
        uint256 _price,
        bool _isEncrypted,
        AccessMode _accessMode,
        bool _isIndex,
        string memory _fileExtension
    ) public returns (uint256) {
        _fileIdCounter++;
        uint256 newFileId = _fileIdCounter;

        files[newFileId] = File({
            owner: payable(msg.sender),
            ipfsCID: _ipfsCID,
            price: _price,
            isEncrypted: _isEncrypted,
            mode: _accessMode,
            isIndex: _isIndex,
            isDeleted: false,
            fileExtension: _fileExtension
        });

        accessRights[newFileId][msg.sender] = true;

        emit FileRegistered(newFileId, msg.sender, _fileExtension);
        return newFileId;
    }
    
    /**
     * @notice Allows the owner to store the master-key-encrypted file key on-chain. 
     */
    function setEncryptedFileKey(uint256 _fileId, bytes memory _encryptedKey) public fileExists(_fileId) onlyFileOwner(_fileId) {
        encryptedFileKeys[_fileId] = _encryptedKey;
    }

    /**
     * @notice Soft-deletes a file by setting its `isDeleted` flag.
     */
    function removeFile(uint256 _fileId) public fileExists(_fileId) onlyFileOwner(_fileId) {
        files[_fileId].isDeleted = true;
        emit FileRemoved(_fileId);
    }

    /**
     * @notice Sets or updates the pointer for one of the user's master indexes.
     */
    function setMasterIndex(string memory _indexName, uint256 _fileId, bytes32 _integrityHash) public {
        masterIndexPointers[msg.sender][_indexName] = IndexPointer(_fileId, _integrityHash);
        emit MasterIndexSet(msg.sender, _indexName, _fileId);
    }

    function requestAccess(uint256 _fileId) public fileExists(_fileId) notDeleted(_fileId) {
        File storage file = files[_fileId]; 
        require(file.owner != msg.sender, "Owner cannot request access to their own file.");
        require(file.mode == AccessMode.SHARED, "Can only request access to SHARED files.");
        require(!accessRequests[_fileId][msg.sender], "Request already pending.");

        accessRequests[_fileId][msg.sender] = true;
        
        emit AccessRequested(_fileId,msg.sender,file.owner);
    }
    
    /**
     * @notice Allows a file owner to approve a pending access request.
     */
    function approveAccessRequest(uint256 _fileId, address _userAddress) public fileExists(_fileId) onlyFileOwner(_fileId) {
        require(accessRequests[_fileId][_userAddress], "No pending access request from this user.");
        accessRequests[_fileId][_userAddress] = false; 
        accessRights[_fileId][_userAddress] = true;
        emit AccessGranted(_fileId, msg.sender, _userAddress);
    }

    /**
     * @notice Allows a file owner to explicitly deny a pending access request.
     */
    function denyAccessRequest(uint256 _fileId, address _userAddress) public fileExists(_fileId) onlyFileOwner(_fileId) {
        require(accessRequests[_fileId][_userAddress], "No pending access request from this user.");
        accessRequests[_fileId][_userAddress] = false; 
        emit AccessRequestDenied(_fileId, msg.sender, _userAddress);
    }

    /**
     * @notice Allows a file owner to grant access directly, without a prior request.
     */
    function grantAccess(uint256 _fileId, address _userAddress) public fileExists(_fileId) onlyFileOwner(_fileId) {
        accessRights[_fileId][_userAddress] = true;
        emit AccessGranted(_fileId, msg.sender, _userAddress);
    }

    /**
     * @notice Publishes the IPFS location of the key for a user who has been granted access.
     */
    function putKeyForOtherUser(uint256 _fileId, address _userAddress, string memory _keyLocationCID) public fileExists(_fileId) onlyFileOwner(_fileId) {
        require(accessRights[_fileId][_userAddress], "User does not have access rights to this file.");
        grantedKeyLocations[_fileId][_userAddress] = _keyLocationCID;
        emit KeyForUserPublished(_fileId, _userAddress, _keyLocationCID);
    }

    /**
     * @notice Allows a user to purchase access to a PAID file.
     */
    function purchaseFile(uint256 _fileId) public payable fileExists(_fileId) notDeleted(_fileId) {
        File storage file = files[_fileId];
        require(file.mode == AccessMode.PAID, "This file is not for sale.");
        require(msg.value >= file.price, "Insufficient payment provided.");
        require(!accessRights[_fileId][msg.sender], "You already have access to this file.");
        accessRequests[_fileId][msg.sender]=true;
        accessRights[_fileId][msg.sender] = true;
        (bool success, ) = file.owner.call{value: msg.value}("");
        require(success, "Payment transfer failed.");
        emit FilePurchased(_fileId, msg.sender, msg.value);
        emit AccessRequested(_fileId,msg.sender,file.owner);
    }

    /**
     * @notice Grants a user permanent access to an entire file category (e.g., all shared files).
     */
    function grantIndexAccess(string memory _indexName, address _user, string memory _keyLocationCID) public {
        require(msg.sender != _user, "Cannot grant access to yourself.");
        require(bytes(_keyLocationCID).length > 0, "Key CID cannot be empty.");
        indexAccessKeyLocations[msg.sender][_indexName][_user] = _keyLocationCID;
        emit IndexAccessGranted(msg.sender, _indexName, _user, _keyLocationCID);
    }

    /**
    * @notice Allows a user to set or update the 32-byte hash of their encrypted Umbral key's IPFS CID.
    * @dev This is the gas-optimized version. The client is responsible for encoding/decoding.
    * @param _ipfsHash The 32-byte hash portion of the IPFS multihash.
    */
    function setEncryptedUmbralKey(bytes32 _ipfsHash) public {
        require(_ipfsHash != bytes32(0), "IPFS hash cannot be empty.");
        encryptedUmbralKeyHashes[msg.sender] = _ipfsHash;
        emit UmbralKeySet(msg.sender, _ipfsHash);
    }

    /**
     * @notice Retrieves the full metadata struct for a given file ID.
     */
    function getFileMetadata(uint256 _fileId) public view fileExists(_fileId) returns (File memory) {
        return files[_fileId];
    }

    /**
     * @notice Retrieves the pointer for a user's specified master index.
     */
    function getMasterIndex(address _ownerAddress, string memory _indexName) public view returns (IndexPointer memory) {
        return masterIndexPointers[_ownerAddress][_indexName];
    }

    /**
     * @notice NEW: A utility function to get the total number of files ever registered.
     */
    function getTotalFiles() public view returns (uint256) {
        return _fileIdCounter;
    }
    /**
     * @notice Allows the owner of a file to retrieve their own encrypted file key.
     */
    function getMyEncryptedKey(uint256 _fileId) public view fileExists(_fileId) onlyFileOwner(_fileId) returns (bytes memory) {
        return encryptedFileKeys[_fileId];
    }

    /**
    * @notice Allows a user to set or update their public Umbral key for sharing.
    * @dev This should be called once during user onboarding.
    * @param _publicKey The user's Umbral Public Key as bytes.
    */
    function setMyUmbralPublicKey(bytes memory _publicKey) public {
        require(_publicKey.length > 0, "Public key cannot be empty.");
        if (userFileAccessUpdateBlock[msg.sender] == 0) {
            userFileAccessUpdateBlock[msg.sender] = block.number;
            userIndexAccessUpdateBlock[msg.sender]=block.number;
        }
        userUmbralPublicKeys[msg.sender] = _publicKey;
        emit UmbralPublicKeySet(msg.sender);
    }
    function getUserIndexLastBlock() public view returns (uint256) {
        return userIndexAccessUpdateBlock[msg.sender];
    }
    function getUserFileLastBlock() public view returns (uint256) {
        return userFileAccessUpdateBlock[msg.sender];
    }
    function updateUserFileLastBlock(uint256 block_number) public{
        userFileAccessUpdateBlock[msg.sender]=block_number;
    }
    function updateUserIndexLastBlock(uint256 block_number) public{
        userIndexAccessUpdateBlock[msg.sender]=block_number;
    }

    /**
    * @notice Allows a user to formally request browsing access to another user's index.
    * @param _owner The address of the user whose index is being requested.
    * @param _indexName The name of the index (e.g., "shared").
    */
    function requestIndexAccess(address _owner, string memory _indexName) public {
        require(_owner != msg.sender, "Cannot request access to your own index.");
        require(!indexAccessRequests[_owner][_indexName][msg.sender], "Index access request already pending.");
        require(bytes(indexAccessKeyLocations[_owner][_indexName][msg.sender]).length == 0, "Index access already granted.");
        indexAccessRequests[_owner][_indexName][msg.sender] = true;
        emit IndexAccessRequested(_owner, _indexName, msg.sender);
    }

    /**
    * @notice Allows an owner to approve a pending index access request.
    * @dev This function ONLY approves the request. The owner's client must then call
    * grantIndexAccess() in a separate transaction to deliver the key.
    * @param _indexName The name of the index.
    * @param _requester The address of the user who made the request.
    */
    function approveIndexAccessRequest(string memory _indexName, address _requester) public {
        require(indexAccessRequests[msg.sender][_indexName][_requester], "No pending index request from this user.");
        
        indexAccessRequests[msg.sender][_indexName][_requester] = false;
        emit IndexAccessRequestApproved(msg.sender, _indexName, _requester);
    }

    /**
    * @notice Allows an owner to explicitly deny a pending index access request.
    * @param _indexName The name of the index.
    * @param _requester The address of the user who made the request.
    */
    function denyIndexAccessRequest(string memory _indexName, address _requester) public {
        require(indexAccessRequests[msg.sender][_indexName][_requester], "No pending index request from this user.");
        indexAccessRequests[msg.sender][_indexName][_requester] = false;
        emit IndexAccessRequestDenied(msg.sender, _indexName, _requester);
    }
}