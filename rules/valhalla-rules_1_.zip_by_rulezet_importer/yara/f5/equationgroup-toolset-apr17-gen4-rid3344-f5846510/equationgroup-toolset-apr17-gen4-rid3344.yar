rule EquationGroup_Toolset_Apr17_Gen4_RID3344 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fe7ce2fdb245c62e4183c728bc97e966a98fdc8ffd795ed09da23f96e85dcdcd"
      hash2 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
      hash3 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] \"TargetPort\"      %hu" fullword ascii
      $x2 = "---<<<  Complete  >>>---" fullword ascii
      $x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii
      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and ( 1 of ( $x* ) or 2 of them ) )
}