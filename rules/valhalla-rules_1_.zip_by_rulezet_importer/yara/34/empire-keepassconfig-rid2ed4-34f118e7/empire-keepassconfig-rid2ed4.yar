rule Empire_KeePassConfig_RID2ED4 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:31:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}