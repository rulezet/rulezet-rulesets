rule EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1_RID389A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:28:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
      $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
      $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}