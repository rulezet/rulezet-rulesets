rule sig_20160923_91a105f441389167ee020682aeba4a0c {
  meta:
    description = "datamaliciousorder - file 20160923_91a105f441389167ee020682aeba4a0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fbb97f6e8d64dd9d53e14dd815dbf75fbdeebe086e5447fff88b5517d2ea35c"

  strings:
    $s1  = "rowy: 'orjuwuqzy7'" fullword ascii
    $s2  = "var xwigku = new Function({" fullword ascii
    $s3  = "badan: '4999'," fullword ascii
    $s4  = "lure: '7809'," fullword ascii
    $s5  = "asor: 'ytriforacn3'," fullword ascii
    $s6  = "var odjuvni3 = new Function({" fullword ascii
    $s7  = "oxen: \"st\"," fullword ascii
    $s8  = "ajaja: 'yconunda7'" fullword ascii
    $s9  = "jive: 'yk1'," fullword ascii
    $s10 = "var relpujy32 = new Function({" fullword ascii
    $s11 = "} catch (orupur) {}" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}