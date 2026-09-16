rule SUSP_LNX_Sindoor_ELF_Obfuscation_Aug25_RID34DF : DEMO FILE LINUX OBFUS SUSP {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-08-29 15:49:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, LINUX, OBFUS, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "UPX!" 
   condition: 
      filesize < 10MB and uint16 ( 0 ) == 0 and uint16 ( 4 ) > 0 and $s1 in ( 0xc0 .. 0x100 )
}