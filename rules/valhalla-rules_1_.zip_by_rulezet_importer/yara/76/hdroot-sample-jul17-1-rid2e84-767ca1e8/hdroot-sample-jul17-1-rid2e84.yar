rule HDRoot_Sample_Jul17_1_RID2E84 : DEMO EXE FILE MAL {
   meta:
      description = "Detects HDRoot samples"
      author = "Florian Roth"
      reference = "Winnti HDRoot VT"
      date = "2017-07-07 11:17:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6d2ad82f455becc8c830d000633a370857928c584246a7f41fe722cc46c0d113"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "gleupdate.dll" fullword ascii
      $s2 = "\\DosDevices\\%ws\\system32\\%ws" wide
      $s3 = "l\\Driver\\nsiproxy" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and 3 of them )
}