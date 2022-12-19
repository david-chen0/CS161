package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	// "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	// DONT FORGET TO CHECK CAPITALIZED/NON-CAPITALIZED ATTRIBUTES
	Username string
	Password string
	PrivateSignKey userlib.DSSignKey
	PrivateDecryptKey userlib.PKEDecKey
	// FileMapEKey // DONT USE THIS AND USE getArgonKey(userdata.Username, userdata.Password, 16) INSTEAD
	FileMapMACKey []byte // MAC key for the FileMap struct
	FileMapWrapperUUID uuid.UUID // UUID for this user's FileMap in DataStore
}

type FileMapWrapper struct {
	EncryptedFileMap []byte // A map[string]uuid.UUID from filename to UUID of FileHeadWrapper
	MAC []byte // MAC of the EncryptedFileMap using the user's FileMapMACKey
}

type UserWrapper struct {
	EncryptedUser []byte
	Signature []byte
}

type File struct {
	Filename string
	Content []byte
}

type FileWrapper struct {
	EncryptedFile []byte
	MAC []byte
}

type FileNode struct {
	Prev uuid.UUID // UUID of previous FileNodeWrapper in DataStore
	Next uuid.UUID // UUID of next FileNodeWrapper in DataStore
	Current uuid.UUID // UUID of current FileWrapper in DataStore
	Owner string // Owner of the files
}

type FileNodeWrapper struct {
	EncryptedFileNode []byte
	MAC []byte
}

type FileHead struct {
	M []byte
	K []byte
	F uuid.UUID // UUID of the first FileNodeWrapper in DataStore
	// L uuid.UUID // UUID of the last FileNodeWrapper in DataStore for efficient append
}

type LastWrapper struct {
	EncryptedLast []byte // This is the encrypted uuid.UUID of the last FileNodeWrapper in DataStore
	LastMAC []byte // This is the MAC on EncryptedLast, created with the FileHead's symmetric MAC Key
}

type FileHeadWrapper struct {
	EncryptedFileHead []byte // Encrypted using the current user's public encryption key
	Signature []byte // Signed using the current user's signing key

	// WE NEED TO PUT LAST HERE INSTEAD OF IN FILEHEAD BECAUSE PUTTING IN FILEHEAD EXCEEDS RSA BYTE LIMIT
	LastWrapperUUID uuid.UUID // This is the uuid.UUID of the LastWrapper in DataStore
	LastWrapperMAC []byte // This is the MAC on serialized LastWrapperUUID, created with FileHead's symmetric MAC key

	EncryptedSharedUsers []byte // SharedUsers is a map[string]uuid.UUID that maps from shared user's username to the UUID of their FileHeadWrapper for this file; Encrypted using the symmetric encryption key in FileHead
	SharedUsersMAC []byte // MAC of the EncryptedSharedUsers generated using the symmetric MAC Key in FileHead

	// Should probably encrypt this or something but too lazy to do that lol, maybe try that later
	User string // used to check in acceptinvation that the correct user is accepting the invitation. not too big a deal if its attacked
}

// NOTE: The following methods have toy (insecure!) implementations.

// HELPER METHODS
// Get symmetric key of length keyLen from username and password
func getArgonKey(username string, password string, keyLen uint32) (result []byte) {
	userBytes := []byte(username)
	passBytes := []byte(password)
	return userlib.Argon2Key(passBytes, userBytes, keyLen)
}


// hash and then get the uuid, there might be collisions from the hash
func getUserUUID(username string, password string) (result uuid.UUID, e error) {
	hash := userlib.Hash([]byte(username + password))
	return uuid.FromBytes(hash[:16])
}


// Get the user's FileMap
func getFileMap(userdata *User) (fileMap map[string]uuid.UUID, e error) {
	// Get the user's serialized FileMapWrapper from DataStore
	serializedFileMapWrapper, ok := userlib.DatastoreGet(userdata.FileMapWrapperUUID)
	if !ok {
		return nil, errors.New("User does not have a FileMapWrapper stored in DataStore.")
	}

	// Deserialize the user's serialized FileMapWrapper
	var fileMapWrapper FileMapWrapper
	e = json.Unmarshal(serializedFileMapWrapper, &fileMapWrapper)
	if e != nil {
		return nil, e
	}

	// Verify the MAC on the FileMapWrapper
	MAC, e := userlib.HMACEval(userdata.FileMapMACKey, fileMapWrapper.EncryptedFileMap)
	if e != nil {
		return nil, e
	}
	if !userlib.HMACEqual(MAC, fileMapWrapper.MAC) {
		return nil, errors.New("FileMapWrapper's MAC does not match what we expected.")
	}

	// Decrypt the encrypted FileMap
	dKey := getArgonKey(userdata.Username, userdata.Password, 16)
	serializedFileMap := userlib.SymDec(dKey, fileMapWrapper.EncryptedFileMap)

	// Deserialize the serialized FileMap
	var result map[string]uuid.UUID
	e = json.Unmarshal(serializedFileMap, &result)
	if e != nil {
		return nil, e
	}

	// Successfully retrieved FileMap
	return result, nil
}


// Sets the user's FileMap
func setFileMap(userdata *User, fileMap map[string]uuid.UUID) (e error) {
	// Serialize the FileMap
	serializedFileMap, e := json.Marshal(fileMap)
	if e != nil {
		return e
	}

	// Encrypt the serialized FileMap
	IV := userlib.RandomBytes(16)
	argonKey := getArgonKey(userdata.Username, userdata.Password, 16)
	encryptedFileMap := userlib.SymEnc(argonKey, IV, serializedFileMap)

	// Generate a MAC on the encrypted FileMap
	MAC, e := userlib.HMACEval(userdata.FileMapMACKey, encryptedFileMap)
	if e != nil {
		return e
	}

	// Create a new FileMapWrapper and store the elements into the FileWrapper
	var fileMapWrapper FileMapWrapper
	fileMapWrapper.EncryptedFileMap = encryptedFileMap
	fileMapWrapper.MAC = MAC

	// Serialize the FileMapWrapper
	serializedFileMapWrapper, e := json.Marshal(fileMapWrapper)
	if e != nil {
		return e
	}

	// Store the FileMapWrapper back into DataStore
	userlib.DatastoreSet(userdata.FileMapWrapperUUID, serializedFileMapWrapper)

	// Successfully set the user's FileMap
	return nil
}


// Gets the user's FileHeadWrapper struct's UUID corresponding to the input filename or returns an error if none exist
func getFileHeadWrapperUUID(userdata *User, filename string) (fileHeadWrapperUUID uuid.UUID, e error) {
	// Get the user's FileMap
	fileMap, e := getFileMap(userdata)
	if e != nil {
		return uuid.Nil, e
	}

	// Get the UUID corresponding to the filename
	if result, ok := fileMap[filename]; ok {
		return result, nil
	}

	return uuid.Nil, errors.New("No FileHeadWrapper struct corresponding to the input filename for this user")
}


// Gets the user's FileHeadWrapper struct from DataStore
func getFileHeadWrapper(userdata *User, filename string) (fileHeadWrapper *FileHeadWrapper, e error) {
	// Getting the FileHeadWrapper UUID
	fileHeadWrapperUUID, e := getFileHeadWrapperUUID(userdata, filename)
	if e != nil {
		return nil, e
	}

	// Getting the serialized FileSharing from DataStore using the UUID we just got
	serializedFileHeadWrapper, ok := userlib.DatastoreGet(fileHeadWrapperUUID)
	if !ok {
		return nil, errors.New("Requested FileHeadWrapper does not exist in DataStore")
	}

	// Unserializing the serialized FileSharing
	var result FileHeadWrapper
	e = json.Unmarshal(serializedFileHeadWrapper, &result)
	if e != nil {
		return nil, e
	}

	return &result, nil
}


// Gets the user's FileHead struct
func getFileHead(userdata *User, filename string) (fileHead *FileHead, e error) {
	// Getting the FileHeadWrapper
	fileHeadWrapper, e := getFileHeadWrapper(userdata, filename)
	if e != nil {
		return nil, e
	}

	// Check if FileHeadWrapper has been revoked
	if fileHeadWrapper.Signature == nil || fileHeadWrapper.EncryptedSharedUsers == nil || fileHeadWrapper.SharedUsersMAC == nil {
		return nil, errors.New("Requested file has been revoked from user.")
	}

	// Getting the user's public verification key
	verifyKey, ok := userlib.KeystoreGet(userdata.Username + "Verify")
	if !ok {
		return nil, errors.New("User does not have a verify key stored in KeyStore.")
	}

	// Verifying that the encrypted FileHead has not been tampered with
	e = userlib.DSVerify(verifyKey, fileHeadWrapper.EncryptedFileHead, fileHeadWrapper.Signature)
	if e != nil {
		return nil, e
	}

	// Decrypting the encrypted FileHead using the user's private decrypt key
	serializedFileHead, e := userlib.PKEDec(userdata.PrivateDecryptKey, fileHeadWrapper.EncryptedFileHead)
	if e != nil {
		return nil, e
	}

	// Deserializing the serialized FileHead
	var result FileHead
	e = json.Unmarshal(serializedFileHead, &result)
	if e != nil {
		return nil, e
	}

	// FileHead successfully retrieved
	return &result, nil
}


// Gets the FileNode given the FileNodeWrapper's UUID
func getFileNode(fileNodeWrapperUUID uuid.UUID, symDecKey []byte, MACKey []byte) (fileNode *FileNode, e error) {
	// Getting the serialized FileNodeWrapper from DataStore
	serializedFileNodeWrapper, ok := userlib.DatastoreGet(fileNodeWrapperUUID)
	if !ok {
		return nil, errors.New("Requested FileNodeWrapper does not exist in DataStore.")
	}

	// Deserializing the serialized FileNodeWrapper
	var fileNodeWrapper FileNodeWrapper
	e = json.Unmarshal(serializedFileNodeWrapper, &fileNodeWrapper)
	if e != nil {
		return nil, e
	}

	// Verifying that the MAC of the encrypted FileNode matches the MAC in the FileNodeWrapper
	encryptedFileNodeMAC, e := userlib.HMACEval(MACKey, fileNodeWrapper.EncryptedFileNode)
	if e != nil {
		return nil, e
	}
	if !userlib.HMACEqual(encryptedFileNodeMAC, fileNodeWrapper.MAC) {
		return nil, errors.New("MAC on the FileNodeWrapper is not what we expected.")
	}

	// Decrypting the FileNode using the symmetric decryption key
	serializedFileNode := userlib.SymDec(symDecKey, fileNodeWrapper.EncryptedFileNode)

	// Deserializing the serialized FileNode
	var result FileNode
	e = json.Unmarshal(serializedFileNode, &result)
	if e != nil {
		return nil, e
	}

	// FileNode successfully retrieved
	return &result, nil
}


// Get the UUID of the last FileNodeWrapper in DataStore
func getLastFileNodeWrapperUUID(userdata *User, filename string) (lastUUID uuid.UUID, e error) {
	// Get the FileHeadWrapper
	fileHeadWrapper, e := getFileHeadWrapper(userdata, filename)
	if e != nil {
		return uuid.Nil, e
	}

	// Get the FileHead for its MAC key
	fileHead, e := getFileHead(userdata, filename)
	if e != nil {
		return uuid.Nil, e
	}

	// Serialize the LastWrapper UUID
	serializedLastWrapperUUID, e := json.Marshal(fileHeadWrapper.LastWrapperUUID)
	if e != nil {
		return uuid.Nil, e
	}

	// Check the last FileNodeWrapper UUID's MAC
	lastMAC, e := userlib.HMACEval(fileHead.M, serializedLastWrapperUUID)
	if e != nil {
		return uuid.Nil, e
	}
	if !userlib.HMACEqual(lastMAC, fileHeadWrapper.LastWrapperMAC) {
		return uuid.Nil, errors.New("FileHeadWrapper's LastWrapperMAC is not what we expected")
	}

	// Get the serialized LastWrapper from DataStore
	serializedLastWrapper, ok := userlib.DatastoreGet(fileHeadWrapper.LastWrapperUUID)
	if !ok {
		return uuid.Nil, errors.New("Requested LastWrapper does not exist in DataStore")
	}

	// Deserialize the serialized LastWrapper
	var lastWrapper LastWrapper
	e = json.Unmarshal(serializedLastWrapper, &lastWrapper)
	if e != nil {
		return uuid.Nil, e
	}

	// Verify the MAC on the LastWrapper
	lastWrapperMAC, e := userlib.HMACEval(fileHead.M, lastWrapper.EncryptedLast)
	if e != nil {
		return uuid.Nil, e
	}
	if !userlib.HMACEqual(lastWrapperMAC, lastWrapper.LastMAC) {
		return uuid.Nil, errors.New("LastWrapper's MAC is not what we expected")
	}

	// Decrypt the encrypted last FileNodeWrapper UUID
	serializedLast := userlib.SymDec(fileHead.K, lastWrapper.EncryptedLast)

	// Deserialize the serialized last FileNodeWrapper UUID
	var result uuid.UUID
	e = json.Unmarshal(serializedLast, &result)
	if e != nil {
		return uuid.Nil, e
	}

	// Successfully gotten last FileNodeWrapper UUID
	return result, nil
}


// Creates a LastWrapper and returns the necessary elements for FileHeadWrapper
func makeLastWrapper(encryptedLast []byte, lastMAC []byte, toStore uuid.UUID, fileHead *FileHead) (lastWrapperMAC []byte, e error) {
	// Create a LastWrapper and store the elements into the LastWrapper
	var lastWrapper LastWrapper
	lastWrapper.EncryptedLast = encryptedLast
	lastWrapper.LastMAC = lastMAC

	// Serialize the LastWrapper
	serializedLastWrapper, e := json.Marshal(lastWrapper)
	if e != nil {
		return nil, e
	}

	// Toss the serialized LastWrapper into DataStore
	userlib.DatastoreSet(toStore, serializedLastWrapper)

	// Serialize the lastWrapperUUID
	serializedLastWrapperUUID, e := json.Marshal(toStore)
	if e != nil {
		return nil, e
	}

	// Generate a MAC on the serialized lastWrapperUUID using the FileHead's symmetric MAC key
	lastWrapperUUIDMAC, e := userlib.HMACEval(fileHead.M, serializedLastWrapperUUID)

	// Successfully created LastWrapper
	return lastWrapperUUIDMAC, nil
}


// Gets the contents of the file corresponding to the input FileNode
func getFile(fileNode *FileNode, symDecKey []byte, MACKey []byte) (file *File, e error) {
	// Getting the serialized FileWrapper from DataStore
	serializedFileWrapper, ok := userlib.DatastoreGet(fileNode.Current)
	if !ok {
		return nil, errors.New("Requested FileWrapper does not exist in DataStore.")
	}

	// Deserializing the FileWrapper
	var fileWrapper FileWrapper
	e = json.Unmarshal(serializedFileWrapper, &fileWrapper)
	if e != nil {
		return nil, e
	}

	// Verifying that the MAC of the encrypted File matches the MAC in the FileWrapper
	encryptedFileMAC, e := userlib.HMACEval(MACKey, fileWrapper.EncryptedFile)
	if e != nil {
		return nil, e
	}
	if !userlib.HMACEqual(encryptedFileMAC, fileWrapper.MAC) {
		return nil, errors.New("MAC on the FileWrapper is not what we expected.")
	}

	// Decrypting the File using the symmetric decryption key
	serializedFile := userlib.SymDec(symDecKey, fileWrapper.EncryptedFile)

	// Deserializing the File
	var result File
	e = json.Unmarshal(serializedFile, &result)
	if e != nil {
		return nil, e
	}

	// Successfully retrieved File
	return &result, nil
}


// Create an encrypted empty SharedUsers map and its MAC
func createSharedUsers(fileHead *FileHead) (encryptedResult []byte, MAC []byte, e error) {
	// Make the SharedUsers map
	sharedUsers := make(map[string]uuid.UUID)

	// Serialize the SharedUsers map
	serializedSharedUsers, e := json.Marshal(sharedUsers)
	if e != nil {
		return nil, nil, e
	}

	// Generate a random IV for symmetric encryption
	sharedUsersIV := userlib.RandomBytes(16)

	// Encrypt the serialized SharedUsers map using the FileHead's symmetric encryption key
	encryptedSharedUsers := userlib.SymEnc(fileHead.K, sharedUsersIV, serializedSharedUsers)

	// Generate a MAC on the encrypted SharedUsers using the FileHead's symmetric MAC key
	encryptedSharedUsersMAC, e := userlib.HMACEval(fileHead.M, encryptedSharedUsers)
	if e != nil {
		return nil, nil, e
	}

	return encryptedSharedUsers, encryptedSharedUsersMAC, nil
}


// Recursively(in a DFS manner) revokes access to current user and all of their shared users
func revokeSharedUsers(serializedNilFileHead []byte, fileHeadWrapperUUID uuid.UUID, sharedUsername string, fileHead *FileHead) (e error) {
	// Get the serialized FileHeadWrapper from DataStore
	serializedFileHeadWrapper, ok := userlib.DatastoreGet(fileHeadWrapperUUID)
	if !ok {
		return errors.New("FileHeadWrapper does not exist in DataStore.")
	}

	// Deserialize the FileHeadWrapper
	var fileHeadWrapper FileHeadWrapper
	e = json.Unmarshal(serializedFileHeadWrapper, &fileHeadWrapper)
	if e != nil {
		return e
	}

	// Verify the FileHeadWrapper's SharedUsers MAC using FileHead's symmetric MAC key
	sharedUsersMAC, e := userlib.HMACEval(fileHead.M, fileHeadWrapper.EncryptedSharedUsers)
	if e != nil {
		return e
	}
	if !userlib.HMACEqual(sharedUsersMAC, fileHeadWrapper.SharedUsersMAC) {
		return errors.New("SharedUsersMAC is not what we expected.")
	}

	// Decrypt the FileHeadWrapper's encrypted SharedUsers using FileHead's symmetric decrypt key
	serializedSharedUsers := userlib.SymDec(fileHead.K, fileHeadWrapper.EncryptedSharedUsers)

	// Deserialize the serialized SharedUsers
	var sharedUsers map[string]uuid.UUID
	e = json.Unmarshal(serializedSharedUsers, &sharedUsers)
	if e != nil {
		return e
	}

	// Loop through the SharedUsers
	for sharedUser, sharedUUID := range sharedUsers {
		// Recursively revoke access to shared users
		e = revokeSharedUsers(serializedNilFileHead, sharedUUID, sharedUser, fileHead)
		if e != nil {
			return e
		}
	}

	// Get the current user's public encryption key
	eKey, ok := userlib.KeystoreGet(sharedUsername + "Encrypt")
	if !ok {
		return errors.New("Current user does not have a public encryption key stored in KeyStore.")
	}

	// Encrypt the serialized nil FileHead using the current user's public encryption key
	encryptedNilFileHead, e := userlib.PKEEnc(eKey, serializedNilFileHead)
	if e != nil {
		return e
	}

	// Create a new FileHeadWrapper and store the elements into the FileHeadWrapper
	var newFileHeadWrapper FileHeadWrapper
	newFileHeadWrapper.EncryptedFileHead = encryptedNilFileHead
	newFileHeadWrapper.Signature = nil
	newFileHeadWrapper.LastWrapperUUID = uuid.Nil
	newFileHeadWrapper.LastWrapperMAC = nil
	newFileHeadWrapper.EncryptedSharedUsers = nil
	newFileHeadWrapper.SharedUsersMAC = nil
	newFileHeadWrapper.User = ""

	// Serialize the new FileHeadWrapper
	serializedNewFileHeadWrapper, e := json.Marshal(newFileHeadWrapper)
	if e != nil {
		return e
	}

	// Toss the serialized new FileHeadWrapper into DataStore under the old FileHeadWrapper's UUID
	userlib.DatastoreSet(fileHeadWrapperUUID, serializedNewFileHeadWrapper)

	// Successfully revoked current users and all of the current user's shared users access
	return nil
}


// END OF HELPER METHODS









func InitUser(username string, password string) (userdataptr* User, err error) {
	if username == "" {
		return nil, errors.New("Empty username provided.")
	}

	// Checking if username is unique
	_, ok := userlib.KeystoreGet(username + "Encrypt")
	if ok {
		return nil, errors.New("The requested username already exists")
	}
	
	var userdata User
	userdata.Username = username
	userdata.Password = password

	// make signature keys, sign user struct with private key, store public in keystore
	signKey, verifyKey, e := userlib.DSKeyGen()
	if e != nil {
		return nil, e
	}
	userdata.PrivateSignKey = signKey
	userlib.KeystoreSet(username + "Verify", verifyKey)

	// make encryption keys, store private encrypt key in user, store public in keystore
	eKey, dKey, e := userlib.PKEKeyGen()
	if e != nil {
		return nil, e
	}
	userdata.PrivateDecryptKey = dKey
	userlib.KeystoreSet(username + "Encrypt", eKey)

	// Generate a random MAC key for the user's FileMap
	userdata.FileMapMACKey = userlib.RandomBytes(16)

	// Create an empty FileMap
	fileMap := make(map[string]uuid.UUID)

	// Generate a random UUID for the user's FileMapWrapper
	userdata.FileMapWrapperUUID = uuid.New()

	// Store the fileMap into DataStore
	e = setFileMap(&userdata, fileMap)
	if e != nil {
		return nil, e
	}

	// Serializing the User struct
	serializedUserData, e := json.Marshal(userdata)
	if e != nil {
		return nil, e
	}

	// Making the IV, which is used to symmetrically encrypt the user
	IV := userlib.RandomBytes(16)
	argonKey := getArgonKey(userdata.Username, userdata.Password, 16)
	encryptedUser := userlib.SymEnc(argonKey, IV, serializedUserData)

	// Creating a signature of the unencrypted user
	signature, e := userlib.DSSign(signKey, encryptedUser)
	if e != nil {
		return nil, e
	}

	// Creating the UserWrapper and storing the elements into it
	var userWrapper UserWrapper
	userWrapper.EncryptedUser = encryptedUser
	userWrapper.Signature = signature

	// Serializing the UserWrapper
	serializedUserWrapper, e := json.Marshal(userWrapper)
	if e != nil {
		return nil, e
	}

	// Hash and then get the uuid, there might be collisions from the hash
	UUID, e := getUserUUID(username, password)
	if e != nil {
		return nil, e
	}
	userlib.DatastoreSet(UUID, serializedUserWrapper)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Getting the UUID of the user's UserWrapper in DataStore determinstically
	UUID, e := getUserUUID(username, password)
	if e != nil {
		return nil, e
	}

	// Getting the serialized UserWrapper from DataStore
	serializedUserWrapper, success := userlib.DatastoreGet(UUID)
	if !success {
		return nil, errors.New("No user in Datastore with input UUID")
	}

	// Unserializing the UserWrapper
	var userWrapper UserWrapper
	e = json.Unmarshal(serializedUserWrapper, &userWrapper)
	if e != nil {
		return nil, e
	}

	// Getting the user's verification key from KeyStore
	verifyKey, success := userlib.KeystoreGet(username + "Verify")
	if !success {
		return nil, errors.New("No key in Datastore with ID: " + username + "Verify")
	}

	// Verifying that the UserWrapper has not been modified using the user's verification key
	e = userlib.DSVerify(verifyKey, userWrapper.EncryptedUser, userWrapper.Signature)
	if e != nil {
		return nil, e
	}

	// Getting the symmetric argonKey generated from the user's username and password
	var keyLen uint32 = 16 // This is the keyLen that we have set
	argonKey := getArgonKey(username, password, keyLen)

	// Decrypting the encrypted User struct
	serializedUserData := userlib.SymDec(argonKey, userWrapper.EncryptedUser)

	// Unserialzing the serialized User struct
	var userdata User
	e = json.Unmarshal(serializedUserData, &userdata)
	if e != nil {
		return nil, e
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Generating the symmetric encryption key and MAC key for the structs
	symEncKey := userlib.RandomBytes(16)
	symMACKey := userlib.RandomBytes(16)

	// Creating a File struct and storing the elements into the File
	var file File
	file.Filename = filename
	file.Content = content

	// Serializing the File struct
	serializedFile, e := json.Marshal(file)
	if e != nil {
		return e
	}

	// Encrypting the File using the symmetric encryption key
	IV := userlib.RandomBytes(16)
	encryptedFile := userlib.SymEnc(symEncKey, IV, serializedFile)

	// Generating a MAC on the encrypted file
	encryptedFileMAC, e := userlib.HMACEval(symMACKey, encryptedFile)
	if e != nil {
		return e
	}

	// Creating a FileWrapper and storing the elements into the FileWrapper
	var fileWrapper FileWrapper
	fileWrapper.EncryptedFile = encryptedFile
	fileWrapper.MAC = encryptedFileMAC

	// Serializing the FileWrapper
	serializedFileWrapper, e := json.Marshal(fileWrapper)
	if e != nil {
		return e
	}

	// Generating a random UUID for the serialized FileWrapper
	fileWrapperUUID := uuid.New()

	// Storing the serialized FileWrapper into DataStore under the UUID we just got
	userlib.DatastoreSet(fileWrapperUUID, serializedFileWrapper)

	// Creating a FileNode and storing the elements into the FileNode
	var fileNode FileNode
	fileNode.Prev = uuid.Nil
	fileNode.Next = uuid.Nil
	fileNode.Current = fileWrapperUUID
	fileNode.Owner = userdata.Username

	// Serializing the FileNode
	serializedFileNode, e := json.Marshal(fileNode)
	if e != nil {
		return e
	}

	// Encrypting the FileNode using the symmetric encryption key
	IV = userlib.RandomBytes(16)
	encryptedFileNode := userlib.SymEnc(symEncKey, IV, serializedFileNode)

	// Generating a MAC on the encrypted FileNode
	encryptedFileNodeMAC, e := userlib.HMACEval(symMACKey, encryptedFileNode)

	// Creating a FileNodeWrapper and storing the elements into the FileNodeWrapper
	var fileNodeWrapper FileNodeWrapper
	fileNodeWrapper.EncryptedFileNode = encryptedFileNode
	fileNodeWrapper.MAC = encryptedFileNodeMAC

	// Serializing the FileNodeWrapper
	serializedFileNodeWrapper, e := json.Marshal(fileNodeWrapper)
	if e != nil {
		return e
	}

	// Generating a random UUID for the serialized FileNodeWrapper
	fileNodeWrapperUUID := uuid.New()

	// Storing the serialized FileNodeWrapper into DataStore under the UUID we just got
	userlib.DatastoreSet(fileNodeWrapperUUID, serializedFileNodeWrapper)

	// Creating a FileHead and storing the elements into the FileHead
	var fileHead FileHead
	fileHead.K = symEncKey
	fileHead.M = symMACKey
	fileHead.F = fileNodeWrapperUUID
	// fileHead.L = fileNodeWrapperUUID

	// Serializing the FileHead
	serializedFileHead, e := json.Marshal(fileHead)
	if e != nil {
		return e
	}

	// Getting the user's public encryption key
	eKey, exists := userlib.KeystoreGet(userdata.Username + "Encrypt")
	if !exists {
		return errors.New("User does not have a public encryption key stored.")
	}
	
	// Encrypting the FileHead using the user's public encryption key
	encryptedFileHead, e := userlib.PKEEnc(eKey, serializedFileHead)
	if e != nil {
		return e
	}

	// Generating a signature on the encrypted FileHead using the user's signing key
	signature, e := userlib.DSSign(userdata.PrivateSignKey, encryptedFileHead)
	if e != nil {
		return e
	}

	// Create encrypted SharedUsers and its MAC
	encryptedSharedUsers, encryptedSharedUsersMAC, e := createSharedUsers(&fileHead)
	if e != nil {
		return e
	}

	// Serialize the last FileNodeWrapper UUID
	serializedLast, e := json.Marshal(fileNodeWrapperUUID)
	if e != nil {
		return e
	}

	// Generate a random IV for symmetric encryption
	IV = userlib.RandomBytes(16)

	// Encrypt the serialized last FileNodeWrapper UUID
	encryptedLast := userlib.SymEnc(fileHead.K, IV, serializedLast)

	// Generate a MAC on the encrypted last FileNodeWrapper UUID
	lastMAC, e := userlib.HMACEval(fileHead.M, encryptedLast)
	if e != nil {
		return e
	}

	// Generate a random new UUID for the LastWrapper
	lastWrapperUUID := uuid.New()

	// Create the LastWrapper and toss it into DataStore
	lastWrapperUUIDMAC, e := makeLastWrapper(encryptedLast, lastMAC, lastWrapperUUID, &fileHead)
	if e != nil {
		return e
	}

	// Creating a FileHeadWrapper and storing the elements into the FileHeadWrapper
	var fileHeadWrapper FileHeadWrapper
	fileHeadWrapper.EncryptedFileHead = encryptedFileHead
	fileHeadWrapper.Signature = signature
	fileHeadWrapper.LastWrapperUUID = lastWrapperUUID
	fileHeadWrapper.LastWrapperMAC = lastWrapperUUIDMAC
	fileHeadWrapper.EncryptedSharedUsers = encryptedSharedUsers
	fileHeadWrapper.SharedUsersMAC = encryptedSharedUsersMAC
	fileHeadWrapper.User = userdata.Username

	// Serializing the FileHeadWrapper
	serializedFileHeadWrapper, e := json.Marshal(fileHeadWrapper)
	if e != nil {
		return e
	}

	// Generating a random UUID for the serialized FileHeadWrapper
	fileHeadWrapperUUID := uuid.New()

	// Storing the serialized FileHeadWrapper into DataStore
	userlib.DatastoreSet(fileHeadWrapperUUID, serializedFileHeadWrapper)

	// Get the user's FileMap
	fileMap, e := getFileMap(userdata)
	if e != nil {
		return e
	}

	// Add our current mapping to the user's FileMap
	fileMap[filename] = fileHeadWrapperUUID

	// Store the newly updated FileMap
	e = setFileMap(userdata, fileMap)
	if e != nil {
		return e
	}

	// Successfully stored file
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get the FileHeadWrapper struct's UUID for later use
	fileHeadWrapperUUID, e := getFileHeadWrapperUUID(userdata, filename)
	if e != nil {
		return e
	}

	// Get the FileHeadWrapper struct for later use
	fileHeadWrapper, e := getFileHeadWrapper(userdata, filename)
	if e != nil {
		return e
	}

	// Get the FileHead struct
	fileHead, e := getFileHead(userdata, filename)
	if e != nil {
		return e
	}
	
	// Create a File struct and store the elements into the File
	var file File
	file.Filename = filename
	file.Content = content

	// Serializing the File
	serializedFile, e := json.Marshal(file)
	if e != nil {
		return e
	}

	// Generating a random IV for symmetric encryption
	IV := userlib.RandomBytes(16)

	// Encrypt the File using the symmetric encryption key
	encryptedFile := userlib.SymEnc(fileHead.K, IV, serializedFile)

	// Generating a MAC on the encrypted File using the symmetric MAC key
	encryptedFileMAC, e := userlib.HMACEval(fileHead.M, encryptedFile)

	// Creating a FileWrapper and storing the elements into the FileWrapper
	var fileWrapper FileWrapper
	fileWrapper.EncryptedFile = encryptedFile
	fileWrapper.MAC = encryptedFileMAC

	// Serializing the FileWrapper
	serializedFileWrapper, e := json.Marshal(fileWrapper)
	if e != nil {
		return e
	}

	// Generating a random UUID for the serialized FileWrapper
	serializedFileWrapperUUID := uuid.New()

	// Tossing the serialized FileWrapper into DataStore under the UUID we just generated
	userlib.DatastoreSet(serializedFileWrapperUUID, serializedFileWrapper)

	// Get the current last FileNodeWrapper UUID
	curFileNodeWrapperUUID, e := getLastFileNodeWrapperUUID(userdata, filename)
	if e != nil {
		return e
	}

	// Get the current last FileNode
	curFileNode, e := getFileNode(curFileNodeWrapperUUID, fileHead.K, fileHead.M)
	if e != nil {
		return e
	}

	// Creating a FileNode and storing the elements into the FileNode
	var fileNode FileNode
	fileNode.Prev = curFileNodeWrapperUUID
	fileNode.Next = uuid.Nil
	fileNode.Current = serializedFileWrapperUUID
	fileNode.Owner = curFileNode.Owner

	// Serializing the FileNode
	serializedFileNode, e := json.Marshal(fileNode)
	if e != nil {
		return e
	}

	// Generating a random IV for symmetric encryption
	IV = userlib.RandomBytes(16)

	// Encrypt the serialized FileNode using the symmetric encryption key
	encryptedFileNode := userlib.SymEnc(fileHead.K, IV, serializedFileNode)

	// Generating a MAC on the encrypted FileNode using the symmetric MAC key
	encryptedFileNodeMAC, e := userlib.HMACEval(fileHead.M, encryptedFileNode)
	if e != nil {
		return e
	}

	// Creating a FileNodeWrapper and storing the elements into the FileNodeWrapper
	var fileNodeWrapper FileNodeWrapper
	fileNodeWrapper.EncryptedFileNode = encryptedFileNode
	fileNodeWrapper.MAC = encryptedFileNodeMAC

	// Serializing the FileNodeWrapper
	serializedFileNodeWrapper, e := json.Marshal(fileNodeWrapper)
	if e != nil {
		return e
	}

	// Generate a random UUID for the serialized FileNodeWrapper
	serializedFileNodeWrapperUUID := uuid.New()

	// Toss the serialized FileNodeWrapper into DataStore with the UUID we just generated
	userlib.DatastoreSet(serializedFileNodeWrapperUUID, serializedFileNodeWrapper)

	// Set the Next attribute of the previous last FileNode
	curFileNode.Next = serializedFileNodeWrapperUUID

	// Serialize the previous last FileNode
	serializedCurFileNode, e := json.Marshal(curFileNode)
	if e != nil {
		return e
	}

	// Generate an IV for symmetric encryption
	IV = userlib.RandomBytes(16)

	// Encrypt the serialized previous last FileNode with the symmetric encryption key
	encryptedCurFileNode := userlib.SymEnc(fileHead.K, IV, serializedCurFileNode)

	// Generate a MAC on the encrytped previous last FileNode with the symmetric MAC key
	encryptedCurFileNodeMAC, e := userlib.HMACEval(fileHead.M, encryptedCurFileNode)

	// Create a FileNodeWrapper for the previous last FileNode and store the elements into the FileNodeWrapper
	var curFileNodeWrapper FileNodeWrapper
	curFileNodeWrapper.EncryptedFileNode = encryptedCurFileNode
	curFileNodeWrapper.MAC = encryptedCurFileNodeMAC

	// Serialize the FileNodeWrapper
	serializedCurFileNodeWrapper, e := json.Marshal(curFileNodeWrapper)
	if e != nil {
		return e
	}

	// Toss the FileNodeWrapper into DataStore under the UUID of the previous last FileNodeWrapper
	userlib.DatastoreSet(curFileNodeWrapperUUID, serializedCurFileNodeWrapper)

	// Serialize the new last FileNodeWrapper UUID
	serializedNewFileNodeWrapperUUID, e := json.Marshal(serializedFileNodeWrapperUUID)
	if e != nil {
		return e
	}

	// Generate an IV for symmetric encryption
	IV = userlib.RandomBytes(16)

	// Encrypt the serialized new last FileNodeWrapper UUID
	encryptedNewFileNodeWrapperUUID := userlib.SymEnc(fileHead.K, IV, serializedNewFileNodeWrapperUUID)

	// Generate a MAC on the encrypted new last FileNodeWrapper UUID
	newLastMAC, e := userlib.HMACEval(fileHead.M, encryptedNewFileNodeWrapperUUID)
	if e != nil {
		return e
	}

	// Create the LastWrapper and toss it into DataStore
	_, e = makeLastWrapper(encryptedNewFileNodeWrapperUUID, newLastMAC, fileHeadWrapper.LastWrapperUUID, fileHead)
	if e != nil {
		return e
	}

	// Create a new FileHeadWrapper and store the elements into the FileHeadWrapper
	var newFileHeadWrapper FileHeadWrapper
	newFileHeadWrapper.EncryptedFileHead = fileHeadWrapper.EncryptedFileHead
	newFileHeadWrapper.Signature = fileHeadWrapper.Signature
	newFileHeadWrapper.LastWrapperUUID = fileHeadWrapper.LastWrapperUUID
	newFileHeadWrapper.LastWrapperMAC = fileHeadWrapper.LastWrapperMAC
	newFileHeadWrapper.EncryptedSharedUsers = fileHeadWrapper.EncryptedSharedUsers
	newFileHeadWrapper.SharedUsersMAC = fileHeadWrapper.SharedUsersMAC

	// Serialize the new FileHeadWrapper
	serializedNewFileHeadWrapper, e := json.Marshal(newFileHeadWrapper)
	if e != nil {
		return e
	}

	// Toss the new FileHeadWrapper into DataStore under the previous UUID
	userlib.DatastoreSet(fileHeadWrapperUUID, serializedNewFileHeadWrapper)

	// Successfully appended content
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Get the FileHead struct
	fileHead, e := getFileHead(userdata, filename)
	if e != nil {
		return nil, e
	}

	// Create a byte array to store the contents of the file nodes we are going to process
	contentStore := make([]byte, 0)

	// Get the first FileNodeWrapper's UUID
	curFileNodeWrapperUUID := fileHead.F

	// Iterating through the FileNodeWrappers
	for true {
		// Get the FileNode
		curFileNode, e := getFileNode(curFileNodeWrapperUUID, fileHead.K, fileHead.M)
		if e != nil {
			return nil, e
		}

		// Get the File
		curFile, e := getFile(curFileNode, fileHead.K, fileHead.M)
		if e != nil {
			return nil, e
		}

		// Add the contents of the file to the byte array
		contentStore = append(contentStore, curFile.Content...)

		// Break the loop if the last FileNode has been processed
		if curFileNode.Next == uuid.Nil {
			break;
		}

		// Advance the loop
		curFileNodeWrapperUUID = curFileNode.Next
	}

	// Successfully loaded file
	return contentStore, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Get the FileHeadWrapper UUID for later use
	fileMap, e := getFileMap(userdata)
	if e != nil {
		return uuid.Nil, e
	}
	fileHeadWrapperUUID, ok := fileMap[filename]
	if !ok {
		return uuid.Nil, errors.New("User does not have a file stored under the filename")
	}

	// Get the FileHeadWrapper struct for later use
	fileHeadWrapper, e := getFileHeadWrapper(userdata, filename)
	if e != nil {
		return uuid.Nil, e
	}

	// Get the FileHead struct
	fileHead, e := getFileHead(userdata, filename)
	if e != nil {
		return uuid.Nil, e
	}

	// Create a new FileHead and set the elements of the FileHead
	var newFileHead FileHead
	newFileHead.M = fileHead.M
	newFileHead.K = fileHead.K
	newFileHead.F = fileHead.F
	// newFileHead.L = fileHead.L

	// Get the public encryption key of our recipient user
	recipientEncryptKey, ok := userlib.KeystoreGet(recipientUsername + "Encrypt")
	if !ok {
		return uuid.Nil, errors.New("Recipient user does not have an encryption key stored in KeyStore.")
	}

	// Serialize the new FileHead
	serializedNewFileHead, e := json.Marshal(newFileHead)
	if e != nil {
		return uuid.Nil, e
	}

	// Encrypt the serialized new FileHead using the recipient user's public encryption key
	encryptedNewFileHead, e := userlib.PKEEnc(recipientEncryptKey, serializedNewFileHead)
	if e != nil {
		return uuid.Nil, e
	}

	// Generate a signature on the encrypted new FileHead using the current user's signing key
	signature, e := userlib.DSSign(userdata.PrivateSignKey, encryptedNewFileHead)
	if e != nil {
		return uuid.Nil, e
	}

	// Create encrypted SharedUsers and its MAC
	encryptedSharedUsers, encryptedSharedUsersMAC, e := createSharedUsers(fileHead)
	if e != nil {
		return uuid.Nil, e
	}

	// Create a new FileHeadWrapper and store the elements into the new FileHeadWrapper
	var newFileHeadWrapper FileHeadWrapper
	newFileHeadWrapper.EncryptedFileHead = encryptedNewFileHead
	newFileHeadWrapper.Signature = signature
	newFileHeadWrapper.LastWrapperUUID = fileHeadWrapper.LastWrapperUUID
	newFileHeadWrapper.LastWrapperMAC = fileHeadWrapper.LastWrapperMAC
	newFileHeadWrapper.EncryptedSharedUsers = encryptedSharedUsers
	newFileHeadWrapper.SharedUsersMAC = encryptedSharedUsersMAC
	newFileHeadWrapper.User = recipientUsername

	// Serialize the new FileHeadWrapper
	serializedNewFileHeadWrapper, e := json.Marshal(newFileHeadWrapper)
	if e != nil {
		return uuid.Nil, e
	}

	// Generate a random UUID for the serialized new FileHeadWrapper
	serializedNewFileHeadWrapperUUID := uuid.New()

	// Toss the serialized new FileHeadWrapper into DataStore under the UUID we just generated
	userlib.DatastoreSet(serializedNewFileHeadWrapperUUID, serializedNewFileHeadWrapper)
	
	// // Get the current user's serialized FileHeadWrapper from DataStore
	// serializedFileHeadWrapper, ok := userlib.DatastoreGet(fileHeadWrapperUUID)
	// if !ok {
	// 	return uuid.Nil, errors.New("Current user's FileHeadWrapper not found in DataStore.")
	// }

	// // Deserialize the serialized FileHeadWrapper
	// var fileHeadWrapper FileHeadWrapper
	// e = json.Unmarshal(serializedFileHeadWrapper, &fileHeadWrapper)
	// if e != nil {
	// 	return uuid.Nil, e
	// }

	// Verify the FileHeadWrapper's SharedUsersMAC using FileHead's symmetric MAC key
	sharedUsersMAC, e := userlib.HMACEval(fileHead.M, fileHeadWrapper.EncryptedSharedUsers)
	if e != nil {
		return uuid.Nil, e
	}
	if !userlib.HMACEqual(sharedUsersMAC, fileHeadWrapper.SharedUsersMAC) {
		return uuid.Nil, errors.New("Current user's SharedUsersMAC is not what we expected.")
	}

	// Decrypt the encrypted SharedUsers using FileHead's symmetric decryption key
	serializedSharedUsers := userlib.SymDec(fileHead.K, fileHeadWrapper.EncryptedSharedUsers)

	// Deserialize the serialized SharedUsers
	var sharedUsers map[string]uuid.UUID
	e = json.Unmarshal(serializedSharedUsers, &sharedUsers)
	if e != nil {
		return uuid.Nil, e
	}

	// Add the serialized new FileHeadWrapper's UUID to the current user's FileHead's SharedUsers map
	sharedUsers[recipientUsername] = serializedNewFileHeadWrapperUUID

	// Serialize SharedUsers
	serializedSharedUsers, e = json.Marshal(sharedUsers)

	// Generating a random IV for symmetric encryption
	sharedUsersIV := userlib.RandomBytes(16)

	// Encrypt the current SharedUsers using FileHead's symmetric encryption key
	encryptedSharedUsers = userlib.SymEnc(fileHead.K, sharedUsersIV, serializedSharedUsers)
	
	// Generate a signature on the encrypted SharedUsers using FileHead's symmetric MAC key
	encryptedSharedUsersMAC, e = userlib.HMACEval(fileHead.M, encryptedSharedUsers)
	if e != nil {
		return uuid.Nil, e
	}

	// Create a new FileHeadWrapper and storing the elements into the FileHeadWrapper
	var newCurrentFileHeadWrapper FileHeadWrapper
	newCurrentFileHeadWrapper.EncryptedFileHead = fileHeadWrapper.EncryptedFileHead
	newCurrentFileHeadWrapper.Signature = fileHeadWrapper.Signature
	newCurrentFileHeadWrapper.LastWrapperUUID = fileHeadWrapper.LastWrapperUUID
	newCurrentFileHeadWrapper.LastWrapperMAC = fileHeadWrapper.LastWrapperMAC
	newCurrentFileHeadWrapper.EncryptedSharedUsers = encryptedSharedUsers
	newCurrentFileHeadWrapper.SharedUsersMAC = encryptedSharedUsersMAC
	newCurrentFileHeadWrapper.User = fileHeadWrapper.User
	
	// Serialize the new FileHeadWrapper
	serializedNewCurrentFileHeadWrapper, e := json.Marshal(newCurrentFileHeadWrapper)
	if e != nil {
		return uuid.Nil, e
	}

	// Overwrite the current FileHeadWrapper in DataStore with the new serialized FileHeadWrapper
	userlib.DatastoreSet(fileHeadWrapperUUID, serializedNewCurrentFileHeadWrapper)

	// Successfully created invitation
	return serializedNewFileHeadWrapperUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Get the user's FileMap
	fileMap, e := getFileMap(userdata)
	if e != nil {
		return e
	}

	// Return an error if the user already has a file stored under filename
	if _, ok := fileMap[filename]; ok {
		// Get the old file's FileHeadWrapper
		oldFileHeadWrapper, e := getFileHeadWrapper(userdata, filename)
		if e != nil {
			return e
		}

		// Only return an error if the file has not been revoked
		if oldFileHeadWrapper.Signature != nil && oldFileHeadWrapper.EncryptedSharedUsers != nil && oldFileHeadWrapper.SharedUsersMAC != nil {
			return errors.New("File already exists in user's filename space")
		}
	}

	// Get serialized FileHeadWrapper from DataStore
	serializedFileHeadWrapper, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invitation pointer not present in DataStore.")
	}

	// Deserialize FileHeadWrapper
	var fileHeadWrapper FileHeadWrapper
	e = json.Unmarshal(serializedFileHeadWrapper, &fileHeadWrapper)
	if e != nil {
		return e
	}

	if fileHeadWrapper.User != userdata.Username {
		return errors.New("The current user is not allowed to accept this invitation")
	}

	// Get the sending user's verify key
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "Verify")
	if !ok {
		return errors.New("Sending user does not have a verify key stored in KeyStore.")
	}

	// Verify the signature of the encrypted FileHead
	e = userlib.DSVerify(verifyKey, fileHeadWrapper.EncryptedFileHead, fileHeadWrapper.Signature)
	if e != nil {
		return e
	}

	// Create signature of encrypted FileHead using current user's signing key
	signature, e := userlib.DSSign(userdata.PrivateSignKey, fileHeadWrapper.EncryptedFileHead)
	if e != nil {
		return e
	}

	// Decrypt the encrypted FileHead
	serializedFileHead, e := userlib.PKEDec(userdata.PrivateDecryptKey, fileHeadWrapper.EncryptedFileHead)
	if e != nil {
		return nil
	}

	// Deserialize the serialized FileHead
	var fileHead FileHead
	e = json.Unmarshal(serializedFileHead, &fileHead)
	if e != nil {
		return e
	}

	// Create encrypted SharedUsers and its MAC
	encryptedSharedUsers, encryptedSharedUsersMAC, e := createSharedUsers(&fileHead)
	if e != nil {
		return e
	}

	// Create a new FileHeadWrapper and store the elements into the FileHeadWrappper
	var newFileHeadWrapper FileHeadWrapper
	newFileHeadWrapper.EncryptedFileHead = fileHeadWrapper.EncryptedFileHead
	newFileHeadWrapper.Signature = signature
	newFileHeadWrapper.LastWrapperUUID = fileHeadWrapper.LastWrapperUUID
	newFileHeadWrapper.LastWrapperMAC = fileHeadWrapper.LastWrapperMAC
	newFileHeadWrapper.EncryptedSharedUsers = encryptedSharedUsers
	newFileHeadWrapper.SharedUsersMAC = encryptedSharedUsersMAC
	newFileHeadWrapper.User = fileHeadWrapper.User
	
	// Serialize the new FileHeadWrapper
	serializedNewFileHeadWrapper, e := json.Marshal(newFileHeadWrapper)
	if e != nil {
		return e
	}

	// Overwrite the current FileHeadWrapper in DataStore with the serialized new FileHeadWrapper
	userlib.DatastoreSet(invitationPtr, serializedNewFileHeadWrapper)

	// Add the current mapping to the FileMap
	fileMap[filename] = invitationPtr

	// Store the FileMap back into DataStore
	setFileMap(userdata, fileMap)

	// Successfully accepted invitation
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Get the FileHead struct
	fileHead, e := getFileHead(userdata, filename)
	if e != nil {
		return e
	}

	// Return an error if the current user is not the owner of the file
	firstFileNode, e := getFileNode(fileHead.F, fileHead.K, fileHead.M)
	if e != nil {
		return e
	}
	if firstFileNode.Owner != userdata.Username {
		return errors.New("Only the owner is allowed to revoke access to files.")
	}

	// Create a FileHead and set all attributes to be null except IsRevoked
	var nilFileHead FileHead
	nilFileHead.M = nil
	nilFileHead.K = nil
	nilFileHead.F = uuid.Nil
	// nilFileHead.L = uuid.Nil

	// Serialize the FileHead
	serializedNilFileHead, e := json.Marshal(nilFileHead)
	if e != nil {
		return e
	}

	// Get current user's FileHeadWrapper's UUID
	fileMap, e := getFileMap(userdata)
	if e != nil {
		return e
	}
	curFileHeadWrapperUUID, ok := fileMap[filename]
	if !ok {
		return errors.New("User does not have a file stored under the filename")
	}

	// Get the serialized FileHeadWrapper from DataStore
	serializedFileHeadWrapper, ok := userlib.DatastoreGet(curFileHeadWrapperUUID)
	if !ok {
		return errors.New("FileHeadWrapper does not exist in DataStore.")
	}

	// Deserialize the FileHeadWrapper
	var fileHeadWrapper FileHeadWrapper
	e = json.Unmarshal(serializedFileHeadWrapper, &fileHeadWrapper)
	if e != nil {
		return e
	}

	// Verify the FileHeadWrapper's SharedUsers MAC using FileHead's symmetric MAC key
	sharedUsersMAC, e := userlib.HMACEval(fileHead.M, fileHeadWrapper.EncryptedSharedUsers)
	if e != nil {
		return e
	}
	if !userlib.HMACEqual(sharedUsersMAC, fileHeadWrapper.SharedUsersMAC) {
		return errors.New("SharedUsersMAC is not what we expected.")
	}

	// Decrypt the FileHeadWrapper's encrypted SharedUsers using FileHead's symmetric decrypt key
	serializedSharedUsers := userlib.SymDec(fileHead.K, fileHeadWrapper.EncryptedSharedUsers)

	// Deserialize the serialized SharedUsers
	var sharedUsers map[string]uuid.UUID
	e = json.Unmarshal(serializedSharedUsers, &sharedUsers)
	if e != nil {
		return e
	}

	// Get the revoke recipient user's shared UUID
	sharedUUID, ok := sharedUsers[recipientUsername]
	if !ok {
		return errors.New("The revoke recipient user is not one of the users that we have shared this file to")
	}

	// Revoke access
	e = revokeSharedUsers(serializedNilFileHead, sharedUUID, recipientUsername, fileHead)
	if e != nil {
		return e
	}

	// Successfully revoked access to file
	return nil
}