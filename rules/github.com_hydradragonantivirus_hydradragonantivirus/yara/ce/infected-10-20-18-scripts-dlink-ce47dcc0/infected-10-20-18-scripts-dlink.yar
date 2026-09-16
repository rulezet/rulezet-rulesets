rule infected_10_20_18_scripts_dlink {
  meta:
    description = "scripts - file dlink"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-20"
    hash1       = "ea5cee148f7cbeb3eb4553b7fc2315c48873acb8322e412a344574e70c5f4e4c"

  strings:
    $x1 = "cd /tmp; wget"
    $x3 = "; chmod 777 sefa.mips; ./sefa.mips dlink.mips; rm -rf sefa.mips" fullword ascii
    $x2 = "cd /tmp; wget"
    $x4 = "; chmod 777 sefa.mpsl; ./sefa.mpsl dlink.mpsl; rm -rf sefa.mpsl" fullword ascii

  condition:
    (uint16(0) == 0x6463 and
      filesize < 1KB and
      (1 of ($x*))
    ) or (all of them)
}