rule Empire_Write_HijackDll_RID2FA2 : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 12:05:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii
      $s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii
      $s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii
   condition: 
      filesize < 500KB and 2 of them
}