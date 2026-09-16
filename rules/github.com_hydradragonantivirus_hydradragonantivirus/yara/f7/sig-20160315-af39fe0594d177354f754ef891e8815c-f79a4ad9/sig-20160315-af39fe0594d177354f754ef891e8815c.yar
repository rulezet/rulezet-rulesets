rule sig_20160315_af39fe0594d177354f754ef891e8815c {
  meta:
    description = "datamaliciousorder - file 20160315_af39fe0594d177354f754ef891e8815c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9098b1f69c6fcff1de5a9bf0b66b86734fbcd6607648fc35ddf39a079dc00c50"

  strings:
    $s1 = "        return WScript[o](r);" fullword ascii
    $s2 = "var delveMin = function() {" fullword ascii
    $s3 = "var motexl1 = function(r) {" fullword ascii
    $s4 = "    var u = String[\"fr\" + \"o\" + \"m\" + \"C\" + \"ha\" + \"rCode\"];" fullword ascii
    $s5 = "        for (r = 0; r < o; r++) lookup[r] = code[r];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}