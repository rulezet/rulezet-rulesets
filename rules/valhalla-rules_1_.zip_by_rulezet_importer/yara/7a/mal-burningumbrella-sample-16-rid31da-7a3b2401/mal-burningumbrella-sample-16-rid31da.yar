rule MAL_BurningUmbrella_Sample_16_RID31DA : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://netimo.net 0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}