rule sig_20160314_c08953977d217bea95f156799ee5091f {
  meta:
    description = "datamaliciousorder - file 20160314_c08953977d217bea95f156799ee5091f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e921d43a31535dc4f2c1e005766ade12c28580824c50dd797aeb11ee105bcc65"

  strings:
    $s1  = "var xfy = (\"2.XMLHTTP xrDZEJL huGet XML ream St BpUWQhKz AD faPpFnT O TuCr D\").split(\" \");" fullword ascii
    $s2  = "var wc = true  , GqjP = xfy[7] + xfy[9] + xfy[11];" fullword ascii
    $s3  = "return IJXsJdt[0] + IJXsJdt[2] + IJXsJdt[4] + \".F\" + IJXsJdt[7] + IJXsJdt[9] + IJXsJdt[12] + IJXsJdt[14];" fullword ascii
    $s4  = "var IJXsJdt = \"Sc CZwIhmR r iZkVnDJFg ipting HRSIWEa NGV ile uliJOhXOiUVxYz System Ru LWxIy Obj IcbfpI ect yEvARzH bkOdQ\".spli" ascii
    $s5  = "EUIWS.open(biEWA,ULbFn,false);" fullword ascii
    $s6  = "var IJXsJdt = \"Sc CZwIhmR r iZkVnDJFg ipting HRSIWEa NGV ile uliJOhXOiUVxYz System Ru LWxIy Obj IcbfpI ect yEvARzH bkOdQ\".spli" ascii
    $s7  = "function dEolF(AezcOP) {" fullword ascii
    $s8  = "function TZdQ(EUIWS,ULbFn,biEWA) {" fullword ascii
    $s9  = "if (x >= zqoIF.length) {break;}" fullword ascii
    $s10 = "function fxBz(aYLAB) {" fullword ascii
    $s11 = "function yDvLTNTkD(WuaGQDBNPQW) {" fullword ascii
    $s12 = "function FauTURjZ(GjU) {" fullword ascii
    $s13 = "function viQVPXw(ynNL,TxElc) {" fullword ascii
    $s14 = "return mibqi.status;" fullword ascii
    $s15 = "function Ntkp(oXYAQ) {" fullword ascii
    $s16 = "return EtNqe;" fullword ascii
    $s17 = "return VkMiJS.position=265-265;" fullword ascii
    $s18 = "function wVKN(plhON) {" fullword ascii
    $s19 = "function rWqG(OgLYU) {" fullword ascii
    $s20 = "function Kwit(zqoIF) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}