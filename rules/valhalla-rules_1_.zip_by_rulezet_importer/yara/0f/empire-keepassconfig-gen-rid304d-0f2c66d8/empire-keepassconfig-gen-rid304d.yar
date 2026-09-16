rule Empire_KeePassConfig_Gen_RID304D : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}