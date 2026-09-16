rule sig_20160831_58b8a7f438e482dd1f108e0a8fc17836 {
  meta:
    description = "datamaliciousorder - file 20160831_58b8a7f438e482dd1f108e0a8fc17836.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d98ad52e4db0085fbcf7d87465a14883e64038923e164d27e23983d4bde290c"

  strings:
    $s1  = "curvy: \"GET\"," fullword ascii
    $s2  = "acor: 17134," fullword ascii
    $s3  = "return enomzekj0;" fullword ascii
    $s4  = "function iqutenihu6() {" fullword ascii
    $s5  = "function nvovbucpo0() {" fullword ascii
    $s6  = "function ppezqo9() {" fullword ascii
    $s7  = "return amcujyco0;" fullword ascii
    $s8  = "return idjijlysp9;" fullword ascii
    $s9  = "function morablel0() {" fullword ascii
    $s10 = "function sretgusraryw3() {" fullword ascii
    $s11 = "return jacexa5;" fullword ascii
    $s12 = "function hwyqoza5() {" fullword ascii
    $s13 = "function wogoqx0() {" fullword ascii
    $s14 = "function byptimvazu1() {" fullword ascii
    $s15 = "return jhaqzusiwel7;" fullword ascii
    $s16 = "return czyqi7;" fullword ascii
    $s17 = "function miqopocjaf7() {" fullword ascii
    $s18 = "function wydymi2() {" fullword ascii
    $s19 = "return atsohp7;" fullword ascii
    $s20 = "function okselopky0() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}