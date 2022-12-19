package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"strconv"
	_ "strings"
	"testing"
	"reflect"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================

func measureBandWidth(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

const bigFile = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})




		Specify("User Does Not Exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob who does not exist yet.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("faker", defaultPassword)
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alice", "badPass")
			Expect(err).ToNot(BeNil())
		})

		Specify("File Does Not Exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice loading file that does not exist yet.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing that passwords of length 0 are supported", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("name samne", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", "hi")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", "hi")
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bob.StoreFile(aliceFile, []byte("ppppp"))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("ppppp")))
		})

		Specify("Testing that we can invite, revoke, and invite again", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Inviting A second Time")

			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can still load the file.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Testing that invite chains work, and all authorized actions work", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			err = eve.StoreFile(eveFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))


			// Read with Third User Works
			userlib.DebugMsg("Checking that Charles sees expected file data.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// Append with Third User Works
			userlib.DebugMsg("Charles appending to file %s, content: %s", charlesFile, contentThree)
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			userlib.DebugMsg("Share invite to user")
			_, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())
		})

		Specify("Testing invalid permissions", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append without permission")
			err = bob.AppendToFile(aliceFile, []byte("noPermissionToAddThis"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Load without permission")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Invite without permission")
			_, err = bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for charles.")
			invite, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoke charles access without permission")
			err = bob.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing that file contents integrity is verified and caught1", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("file1")
			err = alice.StoreFile("tamper1", []byte("tamper1"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("file2")
			err = alice.StoreFile("tamper2", []byte("tamper2"))
			Expect(err).To(BeNil())

			currentMap := make(map[uuid.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				currentMap[k] = v
			}

			err = alice.AppendToFile("tamper1", []byte("Adding to First File"))
			Expect(err).To(BeNil())

			var file1UUID uuid.UUID
			var file1Content []byte

			for k, v := range userlib.DatastoreGetMap() {
				if !reflect.DeepEqual(currentMap[k], v) {
					file1UUID = k
					file1Content = v
				}
			}

			currentMap2 := make(map[uuid.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				currentMap2[k] = v
			}

			err = alice.AppendToFile("tamper2", []byte("Adding to Second File"))
			Expect(err).To(BeNil())

			var file2UUID uuid.UUID
			var file2Content []byte

			for k, v := range userlib.DatastoreGetMap() {
				if !reflect.DeepEqual(currentMap2[k], v) {
					file2UUID = k
					file2Content = v
				}
			}

			userlib.DatastoreSet(file1UUID, file2Content)
			userlib.DatastoreSet(file2UUID, file1Content)

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation("tamperFile", "bob")
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("tamperFile", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		
		Specify("Testing that file contents integrity is verified and caught3", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			// Get AliceFile's UUID
			currentMap := make(map[uuid.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				currentMap[k] = v
			}

			err = alice.AppendToFile(aliceFile, []byte("Adding New Stuff"))
			Expect(err).To(BeNil())

			for k, v := range userlib.DatastoreGetMap() {
				if !reflect.DeepEqual(currentMap[k], v) {
					userlib.DatastoreSet(k, []byte("PUTSMTHHERE"))
				}
			}

			// this should work because we haven't changed anything with bob's copy of the file
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			// this shouldnt be here because storing will just make a new file and change the filemap, so the edited
			// file wont ever be accessed
			// err = alice.StoreFile(aliceFile, []byte(contentOne))
			// Expect(err).ToNot(BeNil())
			
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			// Ensure Error when Loading Edited File
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing that file contents integrity is verified and caught2", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Manually tampering with file")
			datastoreMap := userlib.DatastoreGetMap()

			for key, _ := range datastoreMap {
				userlib.DatastoreSet(key, []byte("PUTSMTHHERE"))
			}			

			// Ensure Error when Loading Edited File
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			// Also alice should be missing too now
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			err = alice.StoreFile("dd", []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("tamper invite", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(invite, []byte("dead invite"))

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("bad invites", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			
			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("double revoke and revoking file dont exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess("doesntExist", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("invite non existing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept same name of file alreasdy have", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("already", []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile("already", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation("already", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "already")
			Expect(err).ToNot(BeNil())
		})

		Specify("Accept same name of file alreasdy have2", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("already", []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile("already", []byte(contentTwo))
			Expect(err).To(BeNil())

			err = charles.StoreFile("already", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles.")
			invite, err := alice.CreateInvitation("already", "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, "new")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles.")
			invite, err = bob.CreateInvitation("already", "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, "new2")
			Expect(err).To(BeNil())	
			
			data, err := charles.LoadFile("already")
			Expect(data).To(Equal([]byte(contentThree)))

			data, err = charles.LoadFile("new")
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = charles.LoadFile("new2")
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Accept file alreasdy have", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())


		})

		Specify("testing that we have unique usernames", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("notunique", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("notunique", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// Specify("Testing Empty File", func() {
		// 	userlib.DebugMsg("Initializing user Alice.")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	err = alice.StoreFile("n", []byte(""))
		// 	Expect(err).ToNot(BeNil())

		// 	err = alice.StoreFile("", []byte("n"))
		// 	Expect(err).To(BeNil())

		// 	data, err := alice.LoadFile("")
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte("n")))
		// })

		Specify("Testing non existing", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Does not exist file so error")
			err = alice.AppendToFile("doesnotexist", []byte("hehe"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles No Exist Yet So Error")
			_, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoke not exist")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoke when he doesnt have access anyway")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing double init", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("testing no username", func() {
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Wrong user accept invite", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("revoke chain", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob creating invite for charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing double store overwrite", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Testing case sensitivity", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			aliceLaptop, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("bandwith1", func() {
			bwWithJustAlice := measureBandWidth(func() {
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
			})

			var curUser string

			i := 20
			for i >= 0 {
				curUser = "alice" + strconv.Itoa(i)
				_, err = client.InitUser(curUser, defaultPassword)
				Expect(err).To(BeNil())
				i -= 1
			}

			bwWithManyUsers := measureBandWidth(func() {
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())
			})

			Expect(bwWithJustAlice > 3*bwWithManyUsers).To(Equal(false))
		})

		Specify("bandwith2", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bwBeforeAppend := measureBandWidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(bigFile))
			Expect(err).To(BeNil())
			

			bwAfterAppend := measureBandWidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			Expect(bwAfterAppend > 3*bwBeforeAppend).To(Equal(false))
		})
	})
})