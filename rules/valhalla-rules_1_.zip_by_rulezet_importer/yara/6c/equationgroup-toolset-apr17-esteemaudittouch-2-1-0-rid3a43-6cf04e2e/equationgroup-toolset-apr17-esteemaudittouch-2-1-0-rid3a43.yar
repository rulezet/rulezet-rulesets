rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0_RID3A43 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Touching the target failed!" fullword ascii
      $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}