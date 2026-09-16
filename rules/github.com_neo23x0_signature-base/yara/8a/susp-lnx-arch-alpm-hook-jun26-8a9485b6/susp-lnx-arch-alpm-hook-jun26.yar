rule SUSP_LNX_ARCH_ALPM_Hook_Jun26 {
   meta:
      description = "Detects suspicious execution commands in Arch ALPM hooks"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      hash = "ba332432f87e68d7fa8c784c60c39ba0d3e2ac06fd8855e82ea49329e2684529"
      score = 70
   strings:
      $s1 = "[Action]"
      $s2 = "Exec = "
      $s3 = "npm install "
      $s4 = "2>/dev/null"
   condition:
      filesize < 5KB
      and all of them
}