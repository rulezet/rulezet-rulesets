rule SUSP_LNX_ARCH_Install_Hook_Jun26 {
   meta:
      description = "Detects suspicious pre and post hooks in Arch install files"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      reference2 = "https://aur.archlinux.org/cgit/aur.git/commit/?h=python-django-js-asset&id=af09b1cf1b59"
      hash = "47c076099e6715ffb0bd357b6832175741e77b88972033cd1f9b55b6ff7e5519"
      hash = "ef735bca8cb2acafe70831e33ed468a3046a61147af694000761970415c7eef1"
      score = 70
   strings:
      $sa1 = "pre_install() {"
      $sa2 = "post_install() {"
      $sa3 = "pre_upgrade() {"
      $sa4 = "post_upgrade() {"
      $sa5 = "pre_remove() {"
      $sa6 = "post_remove() {"

      $sb1 = "npm install "
      $sb2 = "&& 'b''u''n'"

      $fp1 = "#!/bin/sh"
   condition:
      filesize < 5KB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
}