rule SUSP_LNX_ARCH_PKGBUILD_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious PKGBUILD with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      reference2 = "https://aur.archlinux.org/cgit/aur.git/commit/?h=python-django-js-asset&id=af09b1cf1b59"
      hash = "56bed7736d44219215fd912b229c7f765b737db4f6cde256ce264e795310c648"
      hash = "1359814fda7f5ef63f04348439bfb011d7abc0381be6fbb404b04b359d63b61b"
      hash = "3e1f297ab4d261fcad14a865a54d049d75d897d549d03371a5c4bbbc6e10e5cd"
      score = 60
   strings:
            $sa1 = { (0A | 20) 64 65 70 65 6E 64 73 3D 28 [0-15] (6E 70 6D | 62 75 6E) }

            $sb1 = { 69 6E 73 74 61 6C 6C 20 2D 44 6D 36 34 34 20 (22 | 27) [0-100] 2E 68 6F 6F 6B (22 | 27) 0A }
            $sb2 = { 69 6E 73 74 61 6C 6C 3D [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 100KB
      and $sa1
      and 1 of ($sb*)
}