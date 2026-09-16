rule _20160517_1b8619d71c64113c4ce42a2ce7c11845_20160517_20d958382bb9_1065 {
  meta:
    description = "datamaliciousorder - from files 20160517_1b8619d71c64113c4ce42a2ce7c11845.js, 20160517_20d958382bb9b8fc05a2f1516d5ffe08.js, 20160517_c0b312df9701727e7cfbb06dc2e26e38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f93599cfe368cf194768d27dbe32d61fd8c41b1f90a5a97fa4a4af135d33b80"
    hash2       = "1bd23233cc20da1bccc135bdae2416bb616737e14cdc9964fdc2e649a81e116a"
    hash3       = "c02d8ae48f731a29e4b922997785aa2c48dccf4b022c456c547962046c8f624b"

  strings:
    $s1 = "var nConverts1 /* j  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* j  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* j  */;};" fullword ascii
    $s4 = "enjoy1 /* j  */ /* j  */= true;/* j  */" fullword ascii
    $s5 = "could = /* j  */(/* j  */\"noitisop\").split(''/* j  */).reverse(/* j  */).join('');" fullword ascii
    $s6 = "var enjoy1 /* j  */ = false;" fullword ascii
    $s7 = "batch =/* j  */ \"R\" + \"esponseB\"/* j  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}