rule sig_20160305_d8518b0a0a50f323f69d67b07f82c89f {
  meta:
    description = "datamaliciousorder - file 20160305_d8518b0a0a50f323f69d67b07f82c89f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209d981635b9e3922b2b537ec6584eabe8ddb939286798c1a6db8652c6c42a7c"

  strings:
    $s1 = "        return WScript[a](r);" fullword ascii
    $s2 = "var filchixj = function(r) {" fullword ascii
    $s3 = "var balefulszH = function() {" fullword ascii
    $s4 = "        return false === h.raw || h.utf8decode || i ? n.decode(r) : r;" fullword ascii
    $s5 = "        return r + \"====\".slice(r.length % 4 || 4);" fullword ascii
    $s6 = "    var l = String[\"fr\" + \"om\" + \"Ch\" + \"ar\" + \"Code\"];" fullword ascii
    $s7 = "        r = false === h.raw || h.utf8encode || a ? n.encode(r) : r;" fullword ascii
    $s8 = "        decode: function(r) {" fullword ascii
    $s9 = "    h.atob = h.decode = function(r, i) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}