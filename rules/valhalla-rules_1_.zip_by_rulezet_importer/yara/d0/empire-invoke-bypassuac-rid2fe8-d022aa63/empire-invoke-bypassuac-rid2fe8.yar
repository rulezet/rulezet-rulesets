rule Empire_Invoke_BypassUAC_RID2FE8 : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 12:17:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
      $s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii
      $s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii
      $s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii
   condition: 
      filesize < 1200KB and 3 of them
}