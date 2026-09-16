rule sig_20160224_bb87034b6133be17bd3c53a97eb6b080 {
  meta:
    description = "datamaliciousorder - file 20160224_bb87034b6133be17bd3c53a97eb6b080.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5f02c661f81f34b20023874f6dcccad78b69243d8f516495be72a3bc293075b"

  strings:
    $s1 = "    var sentientqUI = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[mercurialBMy](onsetHaS);" fullword ascii
    $s3 = "var endueKtY = function() {" fullword ascii
    $s4 = "var modeZAw = function(gripeTuc) {" fullword ascii
    $s5 = "function btoa(inscrutableeq4, provenderybS, wafflehWg, restrainedJJb, rudimentuzd) {" fullword ascii
    $s6 = "    var disportBpe = false;" fullword ascii
    $s7 = "                        disportBpe = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}