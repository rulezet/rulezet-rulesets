rule SUSP_LNX_Sindoor_ELF_Obfuscation_Aug25 {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 70
      reference = "Internal Research"
      hash = "6879a2b730e391964afe4dbbc29667844ba0c29239be5503b7c86e59e7052443"
   strings:
      $s1 = "UPX!"
   condition:
      filesize < 10MB
      and uint16(0) == 0
      and uint16(4) > 0
      and $s1 in (0xc0..0x100)
}