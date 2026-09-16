rule _7_Zip_Installer: Igor Pavlov {
  meta:
    author = "_pusher_"
    date   = "2015-12"

  strings:
    $a0 = ";!@Install@!" wide ascii nocase
    $a1 = ";!@InstallEnd@!7z" wide ascii nocase
    $a2 = ";!@InstallEnd@!\x0D\x0A7z" wide ascii nocase

  condition:
    $a0 and ($a1 or $a2)

}