rule EquationGroup_Toolset_Apr17_RemoteExecute_Target_RID39FB : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Win32_Process" fullword ascii
      $s2 = "\\\\%ls\\root\\cimv2" fullword wide
      $op1 = { 83 7b 18 01 75 12 83 63 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}