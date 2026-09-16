rule MAL_BurningUmbrella_Sample_19_RID31DD : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:40:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
      hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Cryption.dll" fullword ascii
      $s2 = "tran.exe" fullword ascii
      $s3 = "Kernel.dll" fullword ascii
      $s4 = "Now ready to get the file %s!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them
}