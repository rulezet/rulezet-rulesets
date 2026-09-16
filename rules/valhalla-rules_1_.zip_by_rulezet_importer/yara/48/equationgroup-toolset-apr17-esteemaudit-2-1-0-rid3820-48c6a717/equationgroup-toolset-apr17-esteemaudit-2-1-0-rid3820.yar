rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0_RID3820 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Connected to target %s:%d" fullword ascii
      $x2 = "[-] build_exploit_run_x64():" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}