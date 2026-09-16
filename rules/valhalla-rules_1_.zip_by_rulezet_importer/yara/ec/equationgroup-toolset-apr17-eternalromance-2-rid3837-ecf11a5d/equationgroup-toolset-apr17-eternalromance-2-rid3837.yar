rule EquationGroup_Toolset_Apr17_Eternalromance_2_RID3837 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:11:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      hash3 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Backdoor shellcode written" fullword ascii
      $x2 = "[*] Attempting exploit method %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them )
}