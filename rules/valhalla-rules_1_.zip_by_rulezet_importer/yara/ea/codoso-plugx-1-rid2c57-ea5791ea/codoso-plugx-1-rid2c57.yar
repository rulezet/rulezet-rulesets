rule Codoso_PlugX_1_RID2C57 : DEMO EXE FILE G0073 MAL plugx {
   meta:
      description = "Detects Codoso APT PlugX Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 09:45:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
      hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
      hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"
      tags = "DEMO, EXE, FILE, G0073, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GETPASSWORD1" fullword ascii
      $s2 = "NvSmartMax.dll" fullword ascii
      $s3 = "LICENSEDLG" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them
}