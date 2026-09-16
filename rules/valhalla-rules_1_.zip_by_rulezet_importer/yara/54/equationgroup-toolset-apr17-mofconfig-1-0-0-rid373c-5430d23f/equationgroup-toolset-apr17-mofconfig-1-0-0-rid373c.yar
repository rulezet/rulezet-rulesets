rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0_RID373C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}