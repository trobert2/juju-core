// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package cloudinit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/errgo/errgo"
	"launchpad.net/goyaml"

	"launchpad.net/juju-core/agent"
	"launchpad.net/juju-core/agent/mongo"
	agenttools "launchpad.net/juju-core/agent/tools"
	"launchpad.net/juju-core/cloudinit"
	"launchpad.net/juju-core/constraints"
	"launchpad.net/juju-core/environs/config"
	"launchpad.net/juju-core/instance"
	"launchpad.net/juju-core/juju/osenv"
	"launchpad.net/juju-core/names"
	"launchpad.net/juju-core/state"
	"launchpad.net/juju-core/state/api"
	"launchpad.net/juju-core/state/api/params"
	coretools "launchpad.net/juju-core/tools"
	"launchpad.net/juju-core/upstart"
	"launchpad.net/juju-core/utils"
	"launchpad.net/juju-core/version"
)

// BootstrapStateURLFile is used to communicate to the first bootstrap node
// the URL from which to obtain important state information (instance id and
// hardware characteristics). It is a transient file, only used as the node
// is bootstrapping.
var tmpdir string = osenv.TempDir
var BootstrapStateURLFile string = path.Join(tmpdir, "provider-state-url")

// SystemIdentity is the name of the file where the environment SSH key is kept.
const SystemIdentity = "system-identity"

// fileSchemePrefix is the prefix for file:// URLs.
const fileSchemePrefix = "file://"

// MachineConfig represents initialization information for a new juju machine.
type MachineConfig struct {
	// StateServer specifies whether the new machine will run the
	// mongo and API servers.
	StateServer bool

	// StateServerCert and StateServerKey hold the state server
	// certificate and private key in PEM format; they are required when
	// StateServer is set, and ignored otherwise.
	StateServerCert []byte
	StateServerKey  []byte

	// StatePort specifies the TCP port that will be used
	// by the MongoDB server. It must be non-zero
	// if StateServer is true.
	StatePort int

	// APIPort specifies the TCP port that will be used
	// by the API server. It must be non-zero
	// if StateServer is true.
	APIPort int

	// StateInfo holds the means for the new instance to communicate with the
	// juju state. Unless the new machine is running a state server (StateServer is
	// set), there must be at least one state server address supplied.
	// The entity name must match that of the machine being started,
	// or be empty when starting a state server.
	StateInfo *state.Info

	// APIInfo holds the means for the new instance to communicate with the
	// juju state API. Unless the new machine is running a state server (StateServer is
	// set), there must be at least one state server address supplied.
	// The entity name must match that of the machine being started,
	// or be empty when starting a state server.
	APIInfo *api.Info

	// MachineNonce is set at provisioning/bootstrap time and used to
	// ensure the agent is running on the correct instance.
	MachineNonce string

	// Tools is juju tools to be used on the new machine.
	Tools *coretools.Tools

	// DataDir holds the directory that juju state will be put in the new
	// machine.
	DataDir string

	// LogDir holds the directory that juju logs will be written to.
	LogDir string

	// Jobs holds what machine jobs to run.
	Jobs []params.MachineJob

	// CloudInitOutputLog specifies the path to the output log for cloud-init.
	// The directory containing the log file must already exist.
	CloudInitOutputLog string

	// MachineId identifies the new machine.
	MachineId string

	// MachineContainerType specifies the type of container that the machine
	// is.  If the machine is not a container, then the type is "".
	MachineContainerType instance.ContainerType

	// AuthorizedKeys specifies the keys that are allowed to
	// connect to the machine (see cloudinit.SSHAddAuthorizedKeys)
	// If no keys are supplied, there can be no ssh access to the node.
	// On a bootstrap machine, that is fatal. On other
	// machines it will mean that the ssh, scp and debug-hooks
	// commands cannot work.
	AuthorizedKeys string

	// AgentEnvironment defines additional configuration variables to set in
	// the machine agent config.
	AgentEnvironment map[string]string

	// WARNING: this is only set if the machine being configured is
	// a state server node.
	//
	// Config holds the initial environment configuration.
	Config *config.Config

	// Constraints holds the initial environment constraints.
	Constraints constraints.Value

	// StateInfoURL is the URL of a file which contains information about the state server machines.
	StateInfoURL string

	// DisableSSLHostnameVerification can be set to true to tell cloud-init
	// that it shouldn't verify SSL certificates
	DisableSSLHostnameVerification bool

	// SystemPrivateSSHKey is created at bootstrap time and recorded on every
	// node that has an API server. At this stage, that is any machine where
	// StateServer (member above) is set to true.
	SystemPrivateSSHKey string

	// DisablePackageCommands is a flag that specifies whether to suppress
	// the addition of package management commands.
	DisablePackageCommands bool

	// MachineAgentServiceName is the Upstart service name for the Juju machine agent.
	MachineAgentServiceName string

	// MongoServiceName is the Upstart service name for the Mongo database.
	MongoServiceName string

	// ProxySettings define normal http, https and ftp proxies.
	ProxySettings osenv.ProxySettings

	// AptProxySettings define the http, https and ftp proxy settings to use
	// for apt, which may or may not be the same as the normal ProxySettings.
	AptProxySettings osenv.ProxySettings
}

func base64yaml(m *config.Config) string {
	data, err := goyaml.Marshal(m.AllAttrs())
	if err != nil {
		// can't happen, these values have been validated a number of times
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// Configure updates the provided cloudinit.Config with
// configuration to initialize a Juju machine agent.
func Configure(cfg *MachineConfig, c *cloudinit.Config) error {
	if err := ConfigureBasic(cfg, c); err != nil {
		return err
	}
	return ConfigureJuju(cfg, c)
}

// NonceFile is written by cloud-init as the last thing it does.
// The file will contain the machine's nonce. The filename is
// relative to the Juju data-dir.
const NonceFile = "nonce.txt"

var winPowershellHelperFunctions = `

$ErrorActionPreference = "Stop"

function ExecRetry($command, $maxRetryCount = 10, $retryInterval=2)
{
    $currErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true)
    {
        try
        {
            & $command
            break
        }
        catch [System.Exception]
        {
            $retryCount++
            if ($retryCount -ge $maxRetryCount)
            {
                $ErrorActionPreference = $currErrorActionPreference
                throw
            }
            else
            {
                Write-Error $_.Exception
                Start-Sleep $retryInterval
            }
        }
    }

    $ErrorActionPreference = $currErrorActionPreference
}

function create-account ([string]$accountName, [string]$accountDescription, [string]$password) {
	$hostname = hostname
	$comp = [adsi]"WinNT://$hostname"
	$user = $comp.Create("User", $accountName)
	$user.SetPassword($password)
	$user.SetInfo()
	$user.description = $accountDescription
	$user.SetInfo()
	$User.UserFlags[0] = $User.UserFlags[0] -bor 0x10000
	$user.SetInfo()

	$objOU = [ADSI]"WinNT://$hostname/Administrators,group"
	$objOU.add("WinNT://$hostname/$accountName")
}

$Source = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PSCloudbase
{
    public sealed class Win32CryptApi
    {
        public static long CRYPT_SILENT                     = 0x00000040;
        public static long CRYPT_VERIFYCONTEXT              = 0xF0000000;
        public static int PROV_RSA_FULL                     = 1;

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        [return : MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptAcquireContext(ref IntPtr hProv,
                                                      StringBuilder pszContainer, // Don't use string, as Powershell replaces $null with an empty string
                                                      StringBuilder pszProvider, // Don't use string, as Powershell replaces $null with an empty string
                                                      uint dwProvType,
                                                      uint dwFlags);

        [DllImport("Advapi32.dll", EntryPoint = "CryptReleaseContext", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptReleaseContext(IntPtr hProv, Int32 dwFlags);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptGenRandom(IntPtr hProv, uint dwLen, byte[] pbBuffer);

        [DllImport("Kernel32.dll")]
        public static extern uint GetLastError();
    }
}
"@

Add-Type -TypeDefinition $Source -Language CSharp

function Get-RandomPassword
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [int]$Length
    )
    process
    {
        $hProvider = 0
        try
        {
            if(![PSCloudbase.Win32CryptApi]::CryptAcquireContext([ref]$hProvider, $null, $null,
                                                                 [PSCloudbase.Win32CryptApi]::PROV_RSA_FULL,
                                                                 ([PSCloudbase.Win32CryptApi]::CRYPT_VERIFYCONTEXT -bor
                                                                  [PSCloudbase.Win32CryptApi]::CRYPT_SILENT)))
            {
                throw "CryptAcquireContext failed with error: 0x" + "{0:X0}" -f [PSCloudbase.Win32CryptApi]::GetLastError()
            }

            $buffer = New-Object byte[] $Length
            if(![PSCloudbase.Win32CryptApi]::CryptGenRandom($hProvider, $Length, $buffer))
            {
                throw "CryptGenRandom failed with error: 0x" + "{0:X0}" -f [PSCloudbase.Win32CryptApi]::GetLastError()
            }

            $buffer | ForEach-Object { $password += "{0:X0}" -f $_ }
            return $password
        }
        finally
        {
            if($hProvider)
            {
                $retVal = [PSCloudbase.Win32CryptApi]::CryptReleaseContext($hProvider, 0)
            }
        }
    }
}

$SourcePolicy = @"
/*
Original sources available at: https://bitbucket.org/splatteredbits/carbon
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace PSCarbon
{
    public sealed class Lsa
    {
        // ReSharper disable InconsistentNaming
        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_UNICODE_STRING
        {
            internal LSA_UNICODE_STRING(string inputString)
            {
                if (inputString == null)
                {
                    Buffer = IntPtr.Zero;
                    Length = 0;
                    MaximumLength = 0;
                }
                else
                {
                    Buffer = Marshal.StringToHGlobalAuto(inputString);
                    Length = (ushort)(inputString.Length * UnicodeEncoding.CharSize);
                    MaximumLength = (ushort)((inputString.Length + 1) * UnicodeEncoding.CharSize);
                }
            }

            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_OBJECT_ATTRIBUTES
        {
            internal uint Length;
            internal IntPtr RootDirectory;
            internal LSA_UNICODE_STRING ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        // ReSharper disable UnusedMember.Local
        private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
        private const uint POLICY_VIEW_AUDIT_INFORMATION = 0x00000002;
        private const uint POLICY_GET_PRIVATE_INFORMATION = 0x00000004;
        private const uint POLICY_TRUST_ADMIN = 0x00000008;
        private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
        private const uint POLICY_CREATE_SECRET = 0x00000014;
        private const uint POLICY_CREATE_PRIVILEGE = 0x00000040;
        private const uint POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080;
        private const uint POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100;
        private const uint POLICY_AUDIT_LOG_ADMIN = 0x00000200;
        private const uint POLICY_SERVER_ADMIN = 0x00000400;
        private const uint POLICY_LOOKUP_NAMES = 0x00000800;
        private const uint POLICY_NOTIFICATION = 0x00001000;
        // ReSharper restore UnusedMember.Local

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupPrivilegeValue(
            [MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
            [MarshalAs(UnmanagedType.LPTStr)] string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaFreeMemory(IntPtr pBuffer);

        [DllImport("advapi32.dll")]
        private static extern int LsaNtStatusToWinError(long status);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            [MarshalAs(UnmanagedType.U1)]
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);
        // ReSharper restore InconsistentNaming

        private static IntPtr GetIdentitySid(string identity)
        {
            var sid =
                new NTAccount(identity).Translate(typeof (SecurityIdentifier)) as SecurityIdentifier;
            if (sid == null)
            {
                throw new ArgumentException(string.Format("Account {0} not found.", identity));
            }
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            var sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
            return sidPtr;
        }

        private static IntPtr GetLsaPolicyHandle()
        {
            var computerName = Environment.MachineName;
            IntPtr hPolicy;
            var objectAttributes = new LSA_OBJECT_ATTRIBUTES
            {
                Length = 0,
                RootDirectory = IntPtr.Zero,
                Attributes = 0,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            const uint ACCESS_MASK = POLICY_CREATE_SECRET | POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION;
            var machineNameLsa = new LSA_UNICODE_STRING(computerName);
            var result = LsaOpenPolicy(ref machineNameLsa, ref objectAttributes, ACCESS_MASK, out hPolicy);
            HandleLsaResult(result);
            return hPolicy;
        }

        public static string[] GetPrivileges(string identity)
        {
            var sidPtr = GetIdentitySid(identity);
            var hPolicy = GetLsaPolicyHandle();
            var rightsPtr = IntPtr.Zero;

            try
            {

                var privileges = new List<string>();

                uint rightsCount;
                var result = LsaEnumerateAccountRights(hPolicy, sidPtr, out rightsPtr, out rightsCount);
                var win32ErrorCode = LsaNtStatusToWinError(result);
                // the user has no privileges
                if( win32ErrorCode == STATUS_OBJECT_NAME_NOT_FOUND )
                {
                    return new string[0];
                }
                HandleLsaResult(result);

                var myLsaus = new LSA_UNICODE_STRING();
                for (ulong i = 0; i < rightsCount; i++)
                {
                    var itemAddr = new IntPtr(rightsPtr.ToInt64() + (long) (i*(ulong) Marshal.SizeOf(myLsaus)));
                    myLsaus = (LSA_UNICODE_STRING) Marshal.PtrToStructure(itemAddr, myLsaus.GetType());
                    var cvt = new char[myLsaus.Length/UnicodeEncoding.CharSize];
                    Marshal.Copy(myLsaus.Buffer, cvt, 0, myLsaus.Length/UnicodeEncoding.CharSize);
                    var thisRight = new string(cvt);
                    privileges.Add(thisRight);
                }
                return privileges.ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(sidPtr);
                var result = LsaClose(hPolicy);
                HandleLsaResult(result);
                result = LsaFreeMemory(rightsPtr);
                HandleLsaResult(result);
            }
        }

        public static void GrantPrivileges(string identity, string[] privileges)
        {
            var sidPtr = GetIdentitySid(identity);
            var hPolicy = GetLsaPolicyHandle();

            try
            {
                var lsaPrivileges = StringsToLsaStrings(privileges);
                var result = LsaAddAccountRights(hPolicy, sidPtr, lsaPrivileges, (uint)lsaPrivileges.Length);
                HandleLsaResult(result);
            }
            finally
            {
                Marshal.FreeHGlobal(sidPtr);
                var result = LsaClose(hPolicy);
                HandleLsaResult(result);
            }
        }

        const int STATUS_SUCCESS = 0x0;
        const int STATUS_OBJECT_NAME_NOT_FOUND = 0x00000002;
        const int STATUS_ACCESS_DENIED = 0x00000005;
        const int STATUS_INVALID_HANDLE = 0x00000006;
        const int STATUS_UNSUCCESSFUL = 0x0000001F;
        const int STATUS_INVALID_PARAMETER = 0x00000057;
        const int STATUS_NO_SUCH_PRIVILEGE = 0x00000521;
        const int STATUS_INVALID_SERVER_STATE = 0x00000548;
        const int STATUS_INTERNAL_DB_ERROR = 0x00000567;
        const int STATUS_INSUFFICIENT_RESOURCES = 0x000005AA;

        private static readonly Dictionary<int, string> ErrorMessages = new Dictionary<int, string>
                                    {
                                        {STATUS_OBJECT_NAME_NOT_FOUND, "Object name not found. An object in the LSA policy database was not found. The object may have been specified either by SID or by name, depending on its type."},
                                        {STATUS_ACCESS_DENIED, "Access denied. Caller does not have the appropriate access to complete the operation."},
                                        {STATUS_INVALID_HANDLE, "Invalid handle. Indicates an object or RPC handle is not valid in the context used."},
                                        {STATUS_UNSUCCESSFUL, "Unsuccessful. Generic failure, such as RPC connection failure."},
                                        {STATUS_INVALID_PARAMETER, "Invalid parameter. One of the parameters is not valid."},
                                        {STATUS_NO_SUCH_PRIVILEGE, "No such privilege. Indicates a specified privilege does not exist."},
                                        {STATUS_INVALID_SERVER_STATE, "Invalid server state. Indicates the LSA server is currently disabled."},
                                        {STATUS_INTERNAL_DB_ERROR, "Internal database error. The LSA database contains an internal inconsistency."},
                                        {STATUS_INSUFFICIENT_RESOURCES, "Insufficient resources. There are not enough system resources (such as memory to allocate buffers) to complete the call."}
                                    };

        private static void HandleLsaResult(uint returnCode)
        {
            var win32ErrorCode = LsaNtStatusToWinError(returnCode);

            if( win32ErrorCode == STATUS_SUCCESS)
                return;

            if( ErrorMessages.ContainsKey(win32ErrorCode) )
            {
                throw new Win32Exception(win32ErrorCode, ErrorMessages[win32ErrorCode]);
            }

            throw new Win32Exception(win32ErrorCode);
        }

        public static void RevokePrivileges(string identity, string[] privileges)
        {
            var sidPtr = GetIdentitySid(identity);
            var hPolicy = GetLsaPolicyHandle();

            try
            {
                var currentPrivileges = GetPrivileges(identity);
                if (currentPrivileges.Length == 0)
                {
                    return;
                }
                var lsaPrivileges = StringsToLsaStrings(privileges);
                var result = LsaRemoveAccountRights(hPolicy, sidPtr, false, lsaPrivileges, (uint)lsaPrivileges.Length);
                HandleLsaResult(result);
            }
            finally
            {
                Marshal.FreeHGlobal(sidPtr);
                var result = LsaClose(hPolicy);
                HandleLsaResult(result);
            }

        }

        private static LSA_UNICODE_STRING[] StringsToLsaStrings(string[] privileges)
        {
            var lsaPrivileges = new LSA_UNICODE_STRING[privileges.Length];
            for (var idx = 0; idx < privileges.Length; ++idx)
            {
                lsaPrivileges[idx] = new LSA_UNICODE_STRING(privileges[idx]);
            }
            return lsaPrivileges;
        }
    }
}
"@

Add-Type -TypeDefinition $SourcePolicy -Language CSharp

$ServiceChangeErrors = @{}
$ServiceChangeErrors.Add(1, "Not Supported")
$ServiceChangeErrors.Add(2, "Access Denied")
$ServiceChangeErrors.Add(3, "Dependent Services Running")
$ServiceChangeErrors.Add(4, "Invalid Service Control")
$ServiceChangeErrors.Add(5, "Service Cannot Accept Control")
$ServiceChangeErrors.Add(6, "Service Not Active")
$ServiceChangeErrors.Add(7, "Service Request Timeout")
$ServiceChangeErrors.Add(8, "Unknown Failure")
$ServiceChangeErrors.Add(9, "Path Not Found")
$ServiceChangeErrors.Add(10, "Service Already Running")
$ServiceChangeErrors.Add(11, "Service Database Locked")
$ServiceChangeErrors.Add(12, "Service Dependency Deleted")
$ServiceChangeErrors.Add(13, "Service Dependency Failure")
$ServiceChangeErrors.Add(14, "Service Disabled")
$ServiceChangeErrors.Add(15, "Service Logon Failure")
$ServiceChangeErrors.Add(16, "Service Marked For Deletion")
$ServiceChangeErrors.Add(17, "Service No Thread")
$ServiceChangeErrors.Add(18, "Status Circular Dependency")
$ServiceChangeErrors.Add(19, "Status Duplicate Name")
$ServiceChangeErrors.Add(20, "Status Invalid Name")
$ServiceChangeErrors.Add(21, "Status Invalid Parameter")
$ServiceChangeErrors.Add(22, "Status Invalid Service Account")
$ServiceChangeErrors.Add(23, "Status Service Exists")
$ServiceChangeErrors.Add(24, "Service Already Paused")


function SetAssignPrimaryTokenPrivilege($UserName)
{
    $privilege = "SeAssignPrimaryTokenPrivilege"
    if (![PSCarbon.Lsa]::GetPrivileges($UserName).Contains($privilege))
    {
        [PSCarbon.Lsa]::GrantPrivileges($UserName, $privilege)
    }
}

function SetUserLogonAsServiceRights($UserName)
{
    $privilege = "SeServiceLogonRight"
    if (![PSCarbon.Lsa]::GetPrivileges($UserName).Contains($privilege))
    {
        [PSCarbon.Lsa]::GrantPrivileges($UserName, $privilege)
    }
}

$SourceAsUser = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;

namespace PSCloudbase
{
    public class ProcessManager
    {
        const int LOGON32_LOGON_SERVICE = 5;
        const int LOGON32_PROVIDER_DEFAULT = 0;

        const uint GENERIC_ALL_ACCESS = 0x10000000;

        const uint INFINITE = 0xFFFFFFFF;

        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError=true)]
        static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
        static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError=true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
                                                 UInt32 dwMilliseconds);

        [DllImport("Kernel32.dll")]
        static extern int GetLastError();

        [DllImport("Kernel32.dll")]
        extern static int CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr hProcess,
                                              out uint lpExitCode);

        public static uint RunProcess(string userName, string password,
                                      string domain, string cmd,
                                      string arguments)
        {
            bool retValue;
            IntPtr phToken = IntPtr.Zero;
            IntPtr phTokenDup = IntPtr.Zero;
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            try
            {
                retValue = LogonUser(userName, domain, password,
                                     LOGON32_LOGON_SERVICE,
                                     LOGON32_PROVIDER_DEFAULT,
                                     out phToken);
                if(!retValue)
                    throw new Win32Exception(GetLastError());

                var sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);

                retValue = DuplicateTokenEx(
                    phToken, GENERIC_ALL_ACCESS, ref sa,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary, out phTokenDup);
                if(!retValue)
                    throw new Win32Exception(GetLastError());

                STARTUPINFO sInfo = new STARTUPINFO();
                sInfo.lpDesktop = "";

                retValue = CreateProcessAsUser(phTokenDup, cmd, arguments,
                                               ref sa, ref sa, false, 0,
                                               IntPtr.Zero, null,
                                               ref sInfo, out pInfo);
                if(!retValue)
                    throw new Win32Exception(GetLastError());

                WaitForSingleObject(pInfo.hProcess, INFINITE);

                var lastErr = GetLastError();
                if(lastErr != 0)
                    throw new Win32Exception(GetLastError());

                uint exitCode;
                retValue = GetExitCodeProcess(pInfo.hProcess, out exitCode);
                if(!retValue)
                    throw new Win32Exception(GetLastError());

                return exitCode;
            }
            finally
            {
                if(phToken != IntPtr.Zero)
                    CloseHandle(phToken);
                if(phTokenDup != IntPtr.Zero)
                    CloseHandle(phTokenDup);
                if(pInfo.hProcess != IntPtr.Zero)
                    CloseHandle(pInfo.hProcess);
            }
        }
    }
}
"@

Add-Type -TypeDefinition $SourceAsUser -Language CSharp

function Start-ProcessAsUser
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Command,

        [parameter()]
        [string]$Arguments,

        [parameter(Mandatory=$true)]
        [PSCredential]$Credential
    )
    process
    {
        $nc = $Credential.GetNetworkCredential()

        $domain = "."
        if($nc.Domain)
        {
            $domain = $nc.Domain
        }

        [PSCloudbase.ProcessManager]::RunProcess($nc.UserName, $nc.Password,
                                                 $domain, $Command,
                                                 $Arguments)
    }
}

$powershell = "$ENV:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$cmdExe = "$ENV:SystemRoot\System32\cmd.exe"

$juju_passwd = Get-RandomPassword 20
$juju_passwd += "^"
create-account jujud "Juju Admin user" $juju_passwd
$hostname = hostname
$juju_user = "$hostname\jujud"

SetUserLogonAsServiceRights $juju_user

$secpasswd = ConvertTo-SecureString $juju_passwd -AsPlainText -Force
$jujuCreds = New-Object System.Management.Automation.PSCredential ($juju_user, $secpasswd)

`

var winSetPasswdScript = `

Set-Content "C:\juju\bin\save_pass.ps1" @"
Param (
	[Parameter(Mandatory=` + "`$true" + `)]
	[string]` + "`$pass" + `
)

` + "`$secpasswd" + ` = ConvertTo-SecureString ` + "`$pass" + ` -AsPlainText -Force
` + "`$secpasswd" + ` | convertfrom-securestring | Add-Content C:\Juju\Jujud.pass 
"@

`

func WinConfigureBasic(cfg *MachineConfig, c *cloudinit.Config) error {
	// Create a file in a well-defined location containing the machine's
	// nonce. The presence and contents of this file will be verified
	// during bootstrap.
	//
	// Note: this must be the last runcmd we do in ConfigureBasic, as
	// the presence of the nonce file is used to gate the remainder
	// of synchronous bootstrap.
	zipUrl := "https://www.cloudbase.it/downloads/7z920-x64.msi"
	gitUrl := "https://www.cloudbase.it/downloads/Git-1.8.5.2-preview20131230.exe"
	var zipDst = path.Join(osenv.WinTempDir, "7z920-x64.msi")
	var gitDst = path.Join(osenv.WinTempDir, "Git-1.8.5.2-preview20131230.exe")

	c.AddPSScripts(
		fmt.Sprintf(`%s`, winPowershellHelperFunctions),
		fmt.Sprintf(`icacls "%s" /grant "jujud:(OI)(CI)(F)" /T`, utils.PathToWindows(osenv.WinBaseDir)),
        fmt.Sprintf(`mkdir %s`, utils.PathToWindows(osenv.WinTempDir)),
        fmt.Sprintf(`ExecRetry { (new-object System.Net.WebClient).DownloadFile("%s", "%s") }`, 
        	zipUrl, utils.PathToWindows(zipDst)),
		fmt.Sprintf(`cmd.exe /C call msiexec.exe /i "%s" /qb`, utils.PathToWindows(zipDst)),
		fmt.Sprintf(`if ($? -eq $false){ Throw "Failed to install 7zip" }`),
		fmt.Sprintf(`ExecRetry { (new-object System.Net.WebClient).DownloadFile("%s", "%s") }`, 
        	gitUrl, utils.PathToWindows(gitDst)),
		fmt.Sprintf(`cmd.exe /C call "%s" /SILENT`, utils.PathToWindows(gitDst)),
		fmt.Sprintf(`if ($? -eq $false){ Throw "Failed to install Git" }`),
		fmt.Sprintf(`mkdir "%s"`, utils.PathToWindows(osenv.WinBinDir)),
		fmt.Sprintf(`%s`, winSetPasswdScript),
		// fmt.Sprintf(`Start-Process -FilePath powershell.exe -LoadUserProfile -WorkingDirectory '/' -Wait -Credential $jujuCreds -ArgumentList "C:\juju\bin\save_pass.ps1 -pass $juju_passwd"`),
        fmt.Sprintf(`Start-ProcessAsUser -Command $powershell -Arguments "-File C:\juju\bin\save_pass.ps1 $juju_passwd" -Credential $jujuCreds`),
		fmt.Sprintf(`mkdir "%s\locks"`, utils.PathToWindows(osenv.WinLibDir)),
        fmt.Sprintf(`Start-ProcessAsUser -Command $cmdExe -Arguments '/C setx PATH "%%PATH%%;%%PROGRAMFILES(x86)%%\Git\cmd;C:\Juju\bin"' -Credential $jujuCreds`),
		// fmt.Sprintf(`Start-Process -FilePath cmd.exe -LoadUserProfile -WorkingDirectory '/' -Wait -Credential $jujuCreds -ArgumentList '/C call setx PATH "%%PATH%%;%%PROGRAMFILES(x86)%%\Git\cmd;C:\Juju\bin"'`),
	)
	noncefile := path.Join(cfg.DataDir, NonceFile)
	c.AddPSScripts(
		fmt.Sprintf(`Set-Content "%s" "%s"`, utils.PathToWindows(noncefile), shquote(cfg.MachineNonce)),
	)
	return nil
}

func NixConfigureBasic(cfg *MachineConfig, c *cloudinit.Config) error {
		c.AddScripts(
		"set -xe", // ensure we run all the scripts or abort.
	)
	c.AddSSHAuthorizedKeys(cfg.AuthorizedKeys)
	c.SetOutput(cloudinit.OutAll, "| tee -a "+cfg.CloudInitOutputLog, "")
	// Create a file in a well-defined location containing the machine's
	// nonce. The presence and contents of this file will be verified
	// during bootstrap.
	//
	// Note: this must be the last runcmd we do in ConfigureBasic, as
	// the presence of the nonce file is used to gate the remainder
	// of synchronous bootstrap.
	noncefile := path.Join(cfg.DataDir, NonceFile)
	c.AddFile(noncefile, cfg.MachineNonce, 0644)
	return nil
}


// ConfigureBasic updates the provided cloudinit.Config with
// basic configuration to initialise an OS image, such that it can
// be connected to via SSH, and log to a standard location.
//
// Any potentially failing operation should not be added to the
// configuration, but should instead be done in ConfigureJuju.
//
// Note: we don't do apt update/upgrade here so as not to have to wait on
// apt to finish when performing the second half of image initialisation.
// Doing it later brings the benefit of feedback in the face of errors,
// but adds to the running time of initialisation due to lack of activity
// between image bringup and start of agent installation.
func ConfigureBasic(cfg *MachineConfig, c *cloudinit.Config) error {
	if cfg.Tools.Version.Series[:3] == "win"{
		return WinConfigureBasic(cfg, c)
	}
	return NixConfigureBasic(cfg, c)
}

// AddAptCommands update the cloudinit.Config instance with the necessary
// packages, the request to do the apt-get update/upgrade on boot, and adds
// the apt proxy settings if there are any.
func AddAptCommands(proxy osenv.ProxySettings, c *cloudinit.Config) {
	// Bring packages up-to-date.
	c.SetAptUpdate(true)
	c.SetAptUpgrade(true)

	// juju requires git for managing charm directories.
	c.AddPackage("git")
	c.AddPackage("cpu-checker")
	c.AddPackage("bridge-utils")
	c.AddPackage("rsyslog-gnutls")

	// Write out the apt proxy settings
	if (proxy != osenv.ProxySettings{}) {
		filename := utils.AptConfFile
		c.AddBootCmd(fmt.Sprintf(
			`[ -f %s ] || (printf '%%s\n' %s > %s)`,
			filename,
			shquote(utils.AptProxyContent(proxy)),
			filename))
	}
}

// ConfigureJuju updates the provided cloudinit.Config with configuration
// to initialise a Juju machine agent.
func ConfigureJuju(cfg *MachineConfig, c *cloudinit.Config) error {
	if cfg.Tools.Version.Series[:3] == "win"{
		return WinConfigureJuju(cfg, c)
	}
	return NixConfigureJuju(cfg, c)
}

func WinConfigureJuju(cfg *MachineConfig, c *cloudinit.Config) error {
	if err := verifyConfig(cfg); err != nil {
		return err
	}
	toolsJson, err := json.Marshal(cfg.Tools)
	if err != nil {
		return err
	}
	var zipBin string = `C:\Program Files\7-Zip\7z.exe`
	c.AddPSScripts(
		fmt.Sprintf(`$binDir="%s"`, utils.PathToWindows(cfg.jujuTools())),
		fmt.Sprintf(`mkdir '%s\juju'`, utils.PathToWindows(cfg.LogDir)),
		fmt.Sprintf(`mkdir $binDir`),
		fmt.Sprintf(`$WebClient = New-Object System.Net.WebClient`),
		fmt.Sprintf(`[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`),
		fmt.Sprintf(`ExecRetry { $WebClient.DownloadFile('%s', "$binDir\tools.tar.gz") }`, cfg.Tools.URL),
		fmt.Sprintf(`$dToolsHash = (Get-FileHash -Algorithm SHA256 "$binDir\tools.tar.gz").hash`),
		fmt.Sprintf(`$dToolsHash > "$binDir\juju%s.sha256"`,
			cfg.Tools.Version),
		fmt.Sprintf(`if ($dToolsHash.ToLower() -ne "%s"){ Throw "Tools checksum mismatch"}`,
			cfg.Tools.SHA256),
		fmt.Sprintf(`& "%s" x "$binDir\tools.tar.gz" -o"$binDir\"`, zipBin),
		fmt.Sprintf(`& "%s" x "$binDir\tools.tar" -o"$binDir\"`, zipBin),
		fmt.Sprintf(`rm "$binDir\tools.tar*"`),
		fmt.Sprintf(`Set-Content $binDir\downloaded-tools.txt '%s'`, string(toolsJson)),
	)

	machineTag := names.MachineTag(cfg.MachineId)
	_, err = cfg.addAgentInfo(c, machineTag)
	if err != nil {
		return err
	}
	return cfg.winAddMachineAgentToBoot(c, machineTag, cfg.MachineId)
}

func NixConfigureJuju(cfg *MachineConfig, c *cloudinit.Config) error {
	if err := verifyConfig(cfg); err != nil {
		return err
	}

	// Initialise progress reporting. We need to do separately for runcmd
	// and (possibly, below) for bootcmd, as they may be run in different
	// shell sessions.
	initProgressCmd := cloudinit.InitProgressCmd()
	c.AddRunCmd(initProgressCmd)

	// If we're doing synchronous bootstrap or manual provisioning, then
	// ConfigureBasic won't have been invoked; thus, the output log won't
	// have been set. We don't want to show the log to the user, so simply
	// append to the log file rather than teeing.
	if stdout, _ := c.Output(cloudinit.OutAll); stdout == "" {
		c.SetOutput(cloudinit.OutAll, ">> "+cfg.CloudInitOutputLog, "")
		c.AddBootCmd(initProgressCmd)
		c.AddBootCmd(cloudinit.LogProgressCmd("Logging to %s on remote host", cfg.CloudInitOutputLog))
	}

	if !cfg.DisablePackageCommands {
		AddAptCommands(cfg.AptProxySettings, c)
	}

	// Write out the normal proxy settings so that the settings are
	// sourced by bash, and ssh through that.
	c.AddScripts(
		// We look to see if the proxy line is there already as
		// the manual provider may have had it aleady. The ubuntu
		// user may not exist (local provider only).
		`([ ! -e /home/ubuntu/.profile ] || grep -q '.juju-proxy' /home/ubuntu/.profile) || ` +
			`printf '\n# Added by juju\n[ -f "$HOME/.juju-proxy" ] && . "$HOME/.juju-proxy"\n' >> /home/ubuntu/.profile`)
	if (cfg.ProxySettings != osenv.ProxySettings{}) {
		exportedProxyEnv := cfg.ProxySettings.AsScriptEnvironment()
		c.AddScripts(strings.Split(exportedProxyEnv, "\n")...)
		c.AddScripts(
			fmt.Sprintf(
				`[ -e /home/ubuntu ] && (printf '%%s\n' %s > /home/ubuntu/.juju-proxy && chown ubuntu:ubuntu /home/ubuntu/.juju-proxy)`,
				shquote(cfg.ProxySettings.AsScriptEnvironment())))
	}

	// Make the lock dir and change the ownership of the lock dir itself to
	// ubuntu:ubuntu from root:root so the juju-run command run as the ubuntu
	// user is able to get access to the hook execution lock (like the uniter
	// itself does.)
	lockDir := path.Join(cfg.DataDir, "locks")
	c.AddScripts(
		fmt.Sprintf("mkdir -p %s", lockDir),
		// We only try to change ownership if there is an ubuntu user
		// defined, and we determine this by the existance of the home dir.
		fmt.Sprintf("[ -e /home/ubuntu ] && chown ubuntu:ubuntu %s", lockDir),
		fmt.Sprintf("mkdir -p %s", cfg.LogDir),
	)

	// Make a directory for the tools to live in, then fetch the
	// tools and unarchive them into it.
	var copyCmd string
	if strings.HasPrefix(cfg.Tools.URL, fileSchemePrefix) {
		copyCmd = fmt.Sprintf("cp %s $bin/tools.tar.gz", shquote(cfg.Tools.URL[len(fileSchemePrefix):]))
	} else {
		curlCommand := "curl"
		if cfg.DisableSSLHostnameVerification {
			curlCommand = "curl --insecure"
		}
		copyCmd = fmt.Sprintf("%s -o $bin/tools.tar.gz %s", curlCommand, shquote(cfg.Tools.URL))
		c.AddRunCmd(cloudinit.LogProgressCmd("Fetching tools: %s", copyCmd))
	}
	toolsJson, err := json.Marshal(cfg.Tools)
	if err != nil {
		return err
	}
	c.AddScripts(
		"bin="+shquote(cfg.jujuTools()),
		"mkdir -p $bin",
		copyCmd,
		fmt.Sprintf("sha256sum $bin/tools.tar.gz > $bin/juju%s.sha256", cfg.Tools.Version),
		fmt.Sprintf(`grep '%s' $bin/juju%s.sha256 || (echo "Tools checksum mismatch"; exit 1)`,
			cfg.Tools.SHA256, cfg.Tools.Version),
		fmt.Sprintf("tar zxf $bin/tools.tar.gz -C $bin"),
		fmt.Sprintf("rm $bin/tools.tar.gz && rm $bin/juju%s.sha256", cfg.Tools.Version),
		fmt.Sprintf("printf %%s %s > $bin/downloaded-tools.txt", shquote(string(toolsJson))),
	)

	// We add the machine agent's configuration info
	// before running bootstrap-state so that bootstrap-state
	// has a chance to rerwrite it to change the password.
	// It would be cleaner to change bootstrap-state to
	// be responsible for starting the machine agent itself,
	// but this would not be backwardly compatible.
	machineTag := names.MachineTag(cfg.MachineId)
	_, err = cfg.addAgentInfo(c, machineTag)
	if err != nil {
		return err
	}

	// Add the cloud archive cloud-tools pocket to apt sources
	// for series that need it. This gives us up-to-date LXC,
	// MongoDB, and other infrastructure.
	if !cfg.DisablePackageCommands {
		series := cfg.Tools.Version.Series
		MaybeAddCloudArchiveCloudTools(c, series)
	}

	if cfg.StateServer {
		identityFile := cfg.dataFile(SystemIdentity)
		c.AddFile(identityFile, cfg.SystemPrivateSSHKey, 0600)
		if !cfg.DisablePackageCommands {
			// Disable the default mongodb installed by the mongodb-server package.
			// Only do this if the file doesn't exist already, so users can run
			// their own mongodb server if they wish to.
			c.AddBootCmd(
				`[ -f /etc/default/mongodb ] ||
             (echo ENABLE_MONGODB="no" > /etc/default/mongodb)`)

			if cfg.NeedMongoPPA() {
				const key = "" // key is loaded from PPA
				c.AddAptSource("ppa:juju/stable", key, nil)
			}
			c.AddPackageFromTargetRelease("mongodb-server", "precise-updates/cloud-tools")
		}
		certKey := string(cfg.StateServerCert) + string(cfg.StateServerKey)
		c.AddFile(cfg.dataFile("server.pem"), certKey, 0600)
		if err := cfg.addMongoToBoot(c); err != nil {
			return err
		}
		// We temporarily give bootstrap-state a directory
		// of its own so that it can get the state info via the
		// same mechanism as other jujud commands.
		// TODO(rog) 2013-10-04
		// This is redundant now as jujud bootstrap
		// uses the machine agent's configuration.
		// We leave it for the time being for backward compatibility.
		acfg, err := cfg.addAgentInfo(c, "bootstrap")
		if err != nil {
			return err
		}
		cons := cfg.Constraints.String()
		if cons != "" {
			cons = " --constraints " + shquote(cons)
		}
		c.AddRunCmd(cloudinit.LogProgressCmd("Bootstrapping Juju machine agent"))
		c.AddRunCmd(cloudinit.LogProgressCmd(fmt.Sprintf("%s", cfg.Config)))
		c.AddScripts(
			fmt.Sprintf("echo %s > %s", shquote(cfg.StateInfoURL), BootstrapStateURLFile),
			// The bootstrapping is always run with debug on.
			cfg.jujuTools()+"/jujud bootstrap-state"+
				" --data-dir "+shquote(cfg.DataDir)+
				" --env-config "+shquote(base64yaml(cfg.Config))+
				cons+
				" --debug",
			"rm -rf "+shquote(acfg.Dir()),
		)
	}

	return cfg.addMachineAgentToBoot(c, machineTag, cfg.MachineId)
}

func (cfg *MachineConfig) dataFile(name string) string {
	return path.Join(cfg.DataDir, name)
}

// TargetRelease returns a string suitable for use with apt-get --target-release
// based on the machines series.
func (cfg *MachineConfig) TargetRelease() string {
	// Only supported LTS releases have cloud-tools pocket support.
	// Will need to update if-logic for other supported LTS releases
	// as they become available.
	targetRelease := ""
	if cfg.Tools.Version.Series == "precise" {
		targetRelease = "precise-updates/cloud-tools"
	}
	return targetRelease
}

func (cfg *MachineConfig) agentConfig(tag string) (agent.Config, error) {
	// TODO for HAState: the stateHostAddrs and apiHostAddrs here assume that
	// if the machine is a stateServer then to use localhost.  This may be
	// sufficient, but needs thought in the new world order.
	var password string
	if cfg.StateInfo == nil {
		password = cfg.APIInfo.Password
	} else {
		password = cfg.StateInfo.Password
	}
	configParams := agent.AgentConfigParams{
		DataDir:           cfg.DataDir,
		LogDir:            cfg.LogDir,
		Jobs:              cfg.Jobs,
		Tag:               tag,
		UpgradedToVersion: version.Current.Number,
		Password:          password,
		Nonce:             cfg.MachineNonce,
		StateAddresses:    cfg.stateHostAddrs(),
		APIAddresses:      cfg.apiHostAddrs(),
		CACert:            cfg.StateInfo.CACert,
		Values:            cfg.AgentEnvironment,
	}
	if !cfg.StateServer {
		return agent.NewAgentConfig(configParams)
	}
	return agent.NewStateMachineConfig(agent.StateMachineConfigParams{
		AgentConfigParams: configParams,
		StateServerCert:   cfg.StateServerCert,
		StateServerKey:    cfg.StateServerKey,
		StatePort:         cfg.StatePort,
		APIPort:           cfg.APIPort,
	})
}

// addAgentInfo adds agent-required information to the agent's directory
// and returns the agent directory name.
func (cfg *MachineConfig) addAgentInfo(c *cloudinit.Config, tag string) (agent.Config, error) {
	series := cfg.Tools.Version.Series
	acfg, err := cfg.agentConfig(tag)
	if err != nil {
		return nil, err
	}
	acfg.SetValue(agent.AgentServiceName, cfg.MachineAgentServiceName)
	if cfg.StateServer {
		acfg.SetValue(agent.MongoServiceName, cfg.MongoServiceName)
	}
	cmds, err := acfg.WriteCommands(series)
	if err != nil {
		return nil, errgo.Annotate(err, "failed to write commands")
	}
	if series[:3] == "win"{
		c.AddPSScripts(cmds...)
	}else{
		c.AddScripts(cmds...)
	}
	return acfg, nil
}


// MachineAgentWindowsService returns the powershell command for a machine agent service
// based on the tag and machineId passed in.
// TODO: gsamfira: find a better place for this
func MachineAgentWindowsService(name, toolsDir, dataDir, logDir, tag, machineId string) []string {
    jujuServiceWrapper := path.Join(toolsDir, "JujuService.exe")
    logFile := path.Join(logDir, tag+".log")
    jujud := path.Join(toolsDir, "jujud.exe")

    serviceString := fmt.Sprintf(`"%s" "%s" "%s" machine --data-dir "%s" --machine-id "%s" --debug --log-file "%s"`,
        utils.PathToWindows(jujuServiceWrapper), name, utils.PathToWindows(jujud), utils.PathToWindows(dataDir), machineId, utils.PathToWindows(logFile))

    cmd := []string{
    	fmt.Sprintf(`New-Service -Credential $jujuCreds -Name '%s' -DisplayName 'Jujud machine agent' '%s'`, name, serviceString),
    	fmt.Sprintf(`Start-Service %s`, name),
    }
    return cmd
}

//TODO: gsamfira: add agent to startup
func (cfg *MachineConfig) winAddMachineAgentToBoot(c *cloudinit.Config, tag, machineId string) error {
	// Make the agent run via a symbolic link to the actual tools
	// directory, so it can upgrade itself without needing to change
	// the upstart script.
	toolsDir := agenttools.ToolsDir(cfg.DataDir, tag)
	// TODO(dfc) ln -nfs, so it doesn't fail if for some reason that the target already exists
	c.AddPSScripts(fmt.Sprintf(`cmd.exe /C mklink %s %v`, utils.PathToWindows(toolsDir), cfg.Tools.Version))
	name := cfg.MachineAgentServiceName
	cmds := MachineAgentWindowsService(name, toolsDir, cfg.DataDir, cfg.LogDir, tag, machineId)
	c.AddPSScripts(cmds...)
	return nil
}

func (cfg *MachineConfig) addMachineAgentToBoot(c *cloudinit.Config, tag, machineId string) error {
	// Make the agent run via a symbolic link to the actual tools
	// directory, so it can upgrade itself without needing to change
	// the upstart script.
	toolsDir := agenttools.ToolsDir(cfg.DataDir, tag)
	// TODO(dfc) ln -nfs, so it doesn't fail if for some reason that the target already exists
	c.AddScripts(fmt.Sprintf("ln -s %v %s", cfg.Tools.Version, shquote(toolsDir)))

	name := cfg.MachineAgentServiceName
	conf := upstart.MachineAgentUpstartService(name, toolsDir, cfg.DataDir, cfg.LogDir, tag, machineId, nil)
	cmds, err := conf.InstallCommands()
	if err != nil {
		return errgo.Annotatef(err, "cannot make cloud-init upstart script for the %s agent", tag)
	}
	c.AddRunCmd(cloudinit.LogProgressCmd("Starting Juju machine agent (%s)", name))
	c.AddScripts(cmds...)
	return nil
}

func (cfg *MachineConfig) addMongoToBoot(c *cloudinit.Config) error {
	dbDir := path.Join(cfg.DataDir, "db")
	c.AddScripts(
		"mkdir -p "+dbDir+"/journal",
		"chmod 0700 "+dbDir,
		// Otherwise we get three files with 100M+ each, which takes time.
		"dd bs=1M count=1 if=/dev/zero of="+dbDir+"/journal/prealloc.0",
		"dd bs=1M count=1 if=/dev/zero of="+dbDir+"/journal/prealloc.1",
		"dd bs=1M count=1 if=/dev/zero of="+dbDir+"/journal/prealloc.2",
	)

	name := cfg.MongoServiceName
	conf, err := mongo.MongoUpstartService(name, cfg.DataDir, cfg.StatePort)
	if err != nil {
		return err
	}
	cmds, err := conf.InstallCommands()
	if err != nil {
		return errgo.Annotate(err, "cannot make cloud-init upstart script for the state database")
	}
	c.AddRunCmd(cloudinit.LogProgressCmd("Starting MongoDB server (%s)", name))
	c.AddScripts(cmds...)
	return nil
}

// versionDir converts a tools URL into a name
// to use as a directory for storing the tools executables in
// by using the last element stripped of its extension.
func versionDir(toolsURL string) string {
	name := path.Base(toolsURL)
	ext := path.Ext(name)
	return name[:len(name)-len(ext)]
}

func (cfg *MachineConfig) jujuTools() string {
	return agenttools.SharedToolsDir(cfg.DataDir, cfg.Tools.Version)
}

func (cfg *MachineConfig) stateHostAddrs() []string {
	var hosts []string
	if cfg.StateServer {
		hosts = append(hosts, fmt.Sprintf("localhost:%d", cfg.StatePort))
	}
	if cfg.StateInfo != nil {
		hosts = append(hosts, cfg.StateInfo.Addrs...)
	}
	return hosts
}

func (cfg *MachineConfig) apiHostAddrs() []string {
	var hosts []string
	if cfg.StateServer {
		hosts = append(hosts, fmt.Sprintf("localhost:%d", cfg.APIPort))
	}
	if cfg.APIInfo != nil {
		hosts = append(hosts, cfg.APIInfo.Addrs...)
	}
	return hosts
}

const CanonicalCloudArchiveSigningKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.4
Comment: Hostname: keyserver.ubuntu.com

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
p/+af/HU1smBrOfIeRoxb8jQoHu3
=xg4S
-----END PGP PUBLIC KEY BLOCK-----`

// MaybeAddCloudArchiveCloudTools adds the cloud-archive cloud-tools
// pocket to apt sources, if the series requires it.
func MaybeAddCloudArchiveCloudTools(c *cloudinit.Config, series string) {
	if series != "precise" {
		// Currently only precise; presumably we'll
		// need to add each LTS in here as they're
		// added to the cloud archive.
		return
	}
	const url = "http://ubuntu-cloud.archive.canonical.com/ubuntu"
	name := fmt.Sprintf("deb %s %s-updates/cloud-tools main", url, series)
	prefs := &cloudinit.AptPreferences{
		Path:        cloudinit.CloudToolsPrefsPath,
		Explanation: "Pin with lower priority, not to interfere with charms",
		Package:     "*",
		Pin:         fmt.Sprintf("release n=%s-updates/cloud-tools", series),
		PinPriority: 400,
	}
	c.AddAptSource(name, CanonicalCloudArchiveSigningKey, prefs)
}

func (cfg *MachineConfig) NeedMongoPPA() bool {
	series := cfg.Tools.Version.Series
	// 11.10 and earlier are not supported.
	// 12.04 can get a compatible version from the cloud-archive.
	// 13.04 and later ship a compatible version in the archive.
	return series == "quantal"
}

func shquote(p string) string {
	return utils.ShQuote(p)
}

type requiresError string

func (e requiresError) Error() string {
	return "invalid machine configuration: missing " + string(e)
}

func verifyConfig(cfg *MachineConfig) (err error) {
	defer utils.ErrorContextf(&err, "invalid machine configuration")
	if !names.IsMachine(cfg.MachineId) {
		return fmt.Errorf("invalid machine id")
	}
	if cfg.DataDir == "" {
		return fmt.Errorf("missing var directory")
	}
	if cfg.LogDir == "" {
		return fmt.Errorf("missing log directory")
	}
	if len(cfg.Jobs) == 0 {
		return fmt.Errorf("missing machine jobs")
	}
	if cfg.CloudInitOutputLog == "" {
		return fmt.Errorf("missing cloud-init output log path")
	}
	if cfg.Tools == nil {
		return fmt.Errorf("missing tools")
	}
	if cfg.Tools.URL == "" {
		return fmt.Errorf("missing tools URL")
	}
	if cfg.StateInfo == nil {
		return fmt.Errorf("missing state info")
	}
	if len(cfg.StateInfo.CACert) == 0 {
		return fmt.Errorf("missing CA certificate")
	}
	if cfg.APIInfo == nil {
		return fmt.Errorf("missing API info")
	}
	if len(cfg.APIInfo.CACert) == 0 {
		return fmt.Errorf("missing API CA certificate")
	}
	if cfg.MachineAgentServiceName == "" {
		return fmt.Errorf("missing machine agent service name")
	}
	if cfg.StateServer {
		if cfg.MongoServiceName == "" {
			return fmt.Errorf("missing mongo service name")
		}
		if cfg.Config == nil {
			return fmt.Errorf("missing environment configuration")
		}
		if cfg.StateInfo.Tag != "" {
			return fmt.Errorf("entity tag must be blank when starting a state server")
		}
		if cfg.APIInfo.Tag != "" {
			return fmt.Errorf("entity tag must be blank when starting a state server")
		}
		if len(cfg.StateServerCert) == 0 {
			return fmt.Errorf("missing state server certificate")
		}
		if len(cfg.StateServerKey) == 0 {
			return fmt.Errorf("missing state server private key")
		}
		if cfg.StatePort == 0 {
			return fmt.Errorf("missing state port")
		}
		if cfg.APIPort == 0 {
			return fmt.Errorf("missing API port")
		}
		if cfg.SystemPrivateSSHKey == "" {
			return fmt.Errorf("missing system ssh identity")
		}
	} else {
		if len(cfg.StateInfo.Addrs) == 0 {
			return fmt.Errorf("missing state hosts")
		}
		if cfg.StateInfo.Tag != names.MachineTag(cfg.MachineId) {
			return fmt.Errorf("entity tag must match started machine")
		}
		if len(cfg.APIInfo.Addrs) == 0 {
			return fmt.Errorf("missing API hosts")
		}
		if cfg.APIInfo.Tag != names.MachineTag(cfg.MachineId) {
			return fmt.Errorf("entity tag must match started machine")
		}
	}
	if cfg.MachineNonce == "" {
		return fmt.Errorf("missing machine nonce")
	}
	return nil
}
