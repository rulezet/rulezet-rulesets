rule HKTL_Empire_PowerUp_RID2E36 : DEMO HKTL SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
      tags = "DEMO, HKTL, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}