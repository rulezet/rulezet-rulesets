rule GoldenEyeRansomware_Dropper_MalformedZoomit_RID385F : DEMO EXE FILE MAL {
   meta:
      description = "Dropped Executable - "
      author = "Florian Roth"
      reference = "https://www.heise.de/news/Aufgepasst-Neuer-Verschluesselungstrojaner-Goldeneye-verbreitet-sich-rasant-3561396.html"
      date = "2016-12-06 18:18:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
      $n1 = "Mark Russinovich" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}