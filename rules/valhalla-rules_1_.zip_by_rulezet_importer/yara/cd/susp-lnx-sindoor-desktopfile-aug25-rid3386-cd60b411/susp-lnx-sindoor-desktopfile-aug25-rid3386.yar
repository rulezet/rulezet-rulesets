rule SUSP_LNX_Sindoor_DesktopFile_Aug25_RID3386 : DEMO LINUX OBFUS SUSP {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-08-29 14:51:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, OBFUS, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $hdr = "[Desktop Entry]" 
      $s1 = "printf '\\\\x7FELF' | dd of" 
      $s2 = "Future_Note_Warfare_OpSindoor.pdf" 
   condition: 
      filesize < 100KB and $hdr and any of ( $s* )
}