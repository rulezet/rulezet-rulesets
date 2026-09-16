rule EquationGroup_Toolset_Apr17_ParseCapture_RID36C5 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c732d790088a4db148d3291a92de5a449e409704b12e00c7508d75ccd90a03f2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
      $x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
      $x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}