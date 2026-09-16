rule MAL_BurningUmbrella_Sample_14_RID31D8 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:39:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\tmp\\Google_updata.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and 1 of them
}