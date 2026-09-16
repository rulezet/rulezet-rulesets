rule EquationGroup_Toolset_Apr17_EXPA_RID3324 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:35:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
      $x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
      $x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
      $x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 12000KB and 1 of them )
}