rule PowerShell_Suite_Hacktools_Gen_Strings_RID3648 : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects strings from scripts in the PowerShell-Suite repo"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27 16:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "79071ba5a984ee05903d566130467483c197cbc2537f25c1e3d7ae4772211fe0"
      hash2 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
      hash3 = "4f51e7676a4d54c1962760ca0ac81beb28008451511af96652c31f4f40e8eb8e"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "[!] NtCreateThreadEx failed.." fullword ascii
      $ = "[?] Executing mmc.." ascii
      $ = "[!] This method is only supported on 64-bit!" fullword ascii
      $ = "$LNK = [ShellLink.Shortcut]::FromByteArray($LNKHeader.GetBytes())" fullword ascii
      $ = "$CallResult = [UACTokenMagic]::TerminateProcess($ShellExecuteInfo.hProcess, 1)" fullword ascii
      $ = "[!] Unable to open process (as Administrator), this may require SYSTEM access." fullword ascii
      $ = "[!] Error, NTSTATUS Value: " ascii
      $ = "[!] UAC artifact: " ascii
      $ = "[>] Process dump success!" ascii
      $ = "[!] Process dump failed!" ascii
      $ = "[+] Eidolon entry point:" fullword ascii
      $ = "Wait for shellcode to run" fullword ascii
      $ = "$Command = Read-Host \"`nSMB shell\"" fullword ascii
      $ = "Use Netapi32::NetSessionEnum to enumerate active sessions on domain joined machines." fullword ascii
      $ = "Invoke-CreateProcess -Binary C:\\Windows\\System32\\" ascii
      $ = "[?] Thread belongs to: " ascii
      $ = "[?] Operating system core count: " ascii
      $ = "[>] Calling Advapi32::LookupPrivilegeValue --> SeDebugPrivilege" fullword ascii
      $ = "Calling Advapi32::OpenProcessToken --> LSASS" ascii
      $ = "[!] Mmm, something went wrong! GetLastError returned:" ascii
      $ = "if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')" fullword ascii
   condition: 
      filesize < 100KB and 1 of them
}