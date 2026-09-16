rule _20170222_8971850d582ef58c23e954503d21f321_20170409_0aef75156f22_67 {
  meta:
    description = "datamaliciousorder - from files 20170222_8971850d582ef58c23e954503d21f321.js, 20170409_0aef75156f22b586472e03626781f59a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf38c3316cc02b28ef188e0e7c1b519a56f14d1dfd5a2bdcf8e4dec695f3bea"
    hash2       = "b1c327557b36ba5d68ee4653a7a16cd04aeb3364f5a4506bc74a7b8f37806963"

  strings:
    $s1  = "var koqajw = \"file -Win^\";" fullword ascii
    $s2  = "var tigowhe = null;" fullword ascii
    $s3  = "return kerqizu;" fullword ascii
    $s4  = "var kkemli = null;" fullword ascii
    $s5  = "var ojpykut = null;" fullword ascii
    $s6  = "var bxebydo = typeof null;" fullword ascii
    $s7  = "function fxysga() {" fullword ascii
    $s8  = "return syrdotj;" fullword ascii
    $s9  = "function ukfezgyt() {" fullword ascii
    $s10 = "function rriha() {" fullword ascii
    $s11 = "var xubo = undefined;" fullword ascii
    $s12 = "var xvatomxi = typeof undefined;" fullword ascii
    $s13 = "return dbyvwamzu;" fullword ascii
    $s14 = "var wucgefki = typeof null;" fullword ascii
    $s15 = "function uhwucu() {" fullword ascii
    $s16 = "function qotboqbe() {" fullword ascii
    $s17 = "return eloluzx;" fullword ascii
    $s18 = "return uhwenu;" fullword ascii
    $s19 = "function qmifiqnug() {" fullword ascii
    $s20 = "var ugidvyzy = false;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (8 of them)
    ) or (all of them)
}