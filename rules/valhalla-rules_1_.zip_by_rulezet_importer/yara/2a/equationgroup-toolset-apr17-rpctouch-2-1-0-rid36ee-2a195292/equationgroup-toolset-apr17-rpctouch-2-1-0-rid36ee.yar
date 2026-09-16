rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0_RID36EE : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:16:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
      $x2 = "[*] SMB String: %s (%s)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}