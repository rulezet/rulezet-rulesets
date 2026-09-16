rule MAL_BurningUmbrella_Sample_17_RID31DB : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:40:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
      hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
      hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "syshell" fullword wide
      $s2 = "Normal.dotm" fullword ascii
      $s3 = "Microsoft Office Word" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}