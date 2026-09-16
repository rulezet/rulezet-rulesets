rule sig_20161123_1ee26a057a583d87d881caae6068ef5e {
  meta:
    description = "datamaliciousorder - file 20161123_1ee26a057a583d87d881caae6068ef5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fddfdf25d5979c96153b62ae434d7231f6020a2b636a9243140bbd8e8c9dde5"

  strings:
    $s1 = "var himde9 = new Function(zilegsuve9 + ojnezavbozx1 + xuvbywiq7 + jygzujyx8 + bcidary + ctudduco7)();" fullword ascii
    $s2 = "switch (yglymh4[[mranyzda][0]] > 4) {" fullword ascii
    $s3 = "Array.prototype.tcylcamt = function () {" fullword ascii

  condition:
    uint16(0) == 0x7241 and
    all of them
}