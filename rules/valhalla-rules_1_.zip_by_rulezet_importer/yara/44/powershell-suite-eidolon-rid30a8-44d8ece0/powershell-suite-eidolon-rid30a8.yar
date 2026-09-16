rule PowerShell_Suite_Eidolon_RID30A8 : DEMO FILE SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27 12:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
      tags = "DEMO, FILE, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "[+] Eidolon entry point:" ascii
      $ = "C:\\PS> Start-Eidolon -Target C:\\Some\\File.Path -Mimikatz -Verbose" fullword ascii
      $ = "[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 13000KB and 1 of them
}