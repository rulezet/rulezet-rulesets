rule SUSP_LNX_ARCH_SRCINFO_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious .SRCINFO with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      hash = "2ee28d5866fdb46e439678ad92729b1cd71d2d871135d8d56a27cf6a6b49e649"
      score = 60
   strings:
      $s1 = "depends = npm\n"
            $s2 = { 69 6E 73 74 61 6C 6C 20 3D 20 [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 5KB
      and all of them
}