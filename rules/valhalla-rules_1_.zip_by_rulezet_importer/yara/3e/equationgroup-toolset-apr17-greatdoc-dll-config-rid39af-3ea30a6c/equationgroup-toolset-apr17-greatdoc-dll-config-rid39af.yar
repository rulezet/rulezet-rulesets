rule EquationGroup_Toolset_Apr17_greatdoc_dll_config_RID39AF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
      $x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
      $x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
      $x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}