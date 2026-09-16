rule sig_20161102_564cf948c1e63d25631fb5d9c6da6056 {
  meta:
    description = "datamaliciousorder - file 20161102_564cf948c1e63d25631fb5d9c6da6056.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a2cc1763c70c053a7e0df42866b7833abd20f7a4ce5fe107e3acf1aa4d4a79d"

  strings:
    $s1  = "var bofevla = new Function(\"return typeof WScript.StdOut.AtEndOfStream == 'unknown'\")();" fullword ascii
    $s2  = "var ehahawaj = undefined;" fullword ascii
    $s3  = "return 10.3;" fullword ascii
    $s4  = "var ezakonr = null;" fullword ascii
    $s5  = "function kifge() {" fullword ascii
    $s6  = "function uloql() {" fullword ascii
    $s7  = "function defe() {" fullword ascii
    $s8  = "return 34.7607;" fullword ascii
    $s9  = "function leqabd() {" fullword ascii
    $s10 = "var iwtyzivce = undefined;" fullword ascii
    $s11 = "var niflerimd = false;" fullword ascii
    $s12 = "if (jvygsybfezt() == true) {" fullword ascii
    $s13 = "var levpyf = null;" fullword ascii
    $s14 = "var vakifuw = null;" fullword ascii
    $s15 = "var krefpyvtagh = null;" fullword ascii
    $s16 = "switch (kifge()) {" fullword ascii
    $s17 = "var xedqerne = undefined;" fullword ascii
    $s18 = "function ogulj() {" fullword ascii
    $s19 = "var pjezkocgehf = undefined;" fullword ascii
    $s20 = "function jvygsybfezt() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}