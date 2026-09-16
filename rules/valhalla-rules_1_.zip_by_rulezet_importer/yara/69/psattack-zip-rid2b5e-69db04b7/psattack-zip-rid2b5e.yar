rule PSAttack_ZIP_RID2B5E : DEMO FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "PSAttack - Powershell attack tool - file PSAttack.zip"
      author = "Florian Roth"
      reference = "https://github.com/gdssecurity/PSAttack/releases/"
      date = "2016-03-09 09:03:31"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PSAttack.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and all of them
}