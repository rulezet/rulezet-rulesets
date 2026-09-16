rule sig_20160315_ad8291da866359edddc3d9d37a29c7a4 {
  meta:
    description = "datamaliciousorder - file 20160315_ad8291da866359edddc3d9d37a29c7a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "667adc93cf5c4faeb84da6a197707c5e0876fb77411d9a9df2dfd20f6a942338"

  strings:
    $s1 = "        return WScript[r](o);" fullword ascii
    $s2 = "!function(o) {" fullword ascii
    $s3 = "var sonorouszUs = function(o) {" fullword ascii
    $s4 = "var sentientS8y = function() {" fullword ascii
    $s5 = "    var U = String[\"f\" + \"ro\" + \"mC\" + \"h\" + \"arCode\"];" fullword ascii
    $s6 = "        for (o = 0; o < r; o++) lookup[o] = code[o];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}