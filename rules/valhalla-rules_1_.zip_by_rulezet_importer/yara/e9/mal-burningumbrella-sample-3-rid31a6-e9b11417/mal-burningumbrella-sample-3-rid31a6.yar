rule MAL_BurningUmbrella_Sample_3_RID31A6 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}