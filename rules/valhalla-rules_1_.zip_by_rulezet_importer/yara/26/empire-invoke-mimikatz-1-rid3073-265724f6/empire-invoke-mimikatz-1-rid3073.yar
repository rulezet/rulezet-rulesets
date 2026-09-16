rule Empire_Invoke_Mimikatz_1_RID3073 : DEMO S0002 SCRIPT SUSP T1003 T1059_001 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 12:40:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, S0002, SCRIPT, SUSP, T1003, T1059_001, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwc" ascii
      $s2 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)" fullword ascii
      $s3 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii
   condition: 
      filesize < 2500KB and 2 of them
}