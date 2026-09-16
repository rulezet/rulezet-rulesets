rule Empire_Invoke_SMBAutoBrute_RID311A : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
      $s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}