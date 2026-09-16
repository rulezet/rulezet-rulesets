rule Empire_PowerUp_Gen_RID2E1D : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files PowerUp.ps1, PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Result = sc.exe config $($TargetService.Name) binPath= $OriginalPath" fullword ascii
      $s2 = "$Result = sc.exe pause $($TargetService.Name)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}