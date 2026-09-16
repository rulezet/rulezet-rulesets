import "pe"
rule MAL_BurningUmbrella_Sample_1_RID31A4 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:31:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
      tags = "APT, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 } 
      $s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and ( pe.imphash ( ) == "baa93d47220682c04d92f7797d9224ce" and $s1 in ( 0 .. 1024 ) and $s2 in ( 0 .. 1024 ) )
}