rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2_RID36F0 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and 1 of them )
}