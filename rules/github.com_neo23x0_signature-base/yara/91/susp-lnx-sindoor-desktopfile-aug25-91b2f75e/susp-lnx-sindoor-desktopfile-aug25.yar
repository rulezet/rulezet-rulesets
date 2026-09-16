rule SUSP_LNX_Sindoor_DesktopFile_Aug25 {
   meta:
      description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      date = "2025-08-29"
      score = 70
      reference = "Internal Research"
      hash = "9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59"
   strings:
      $hdr = "[Desktop Entry]"
      $s1 = "printf '\\\\x7FELF' | dd of"
      $s2 = "Future_Note_Warfare_OpSindoor.pdf"
   condition:
      filesize < 100KB
      and $hdr
      and any of ($s*)
}