rule sig_20160310_6504df64412b25ad0d00b66b444c88df {
  meta:
    description = "datamaliciousorder - file 20160310_6504df64412b25ad0d00b66b444c88df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e5810a41dbdf8e3c9ad0454d50f1347ad3bea38cf9700f7e07c2b2a9d68d043"

  strings:
    $s1  = "return xopxvJR[0] + xopxvJR[2] + xopxvJR[4] + \".F\" + xopxvJR[7] + xopxvJR[9] + xopxvJR[12] + xopxvJR[14];" fullword ascii
    $s2  = "var ui = true  , CJCY = pnI[7] + pnI[9] + pnI[11];" fullword ascii
    $s3  = "var pnI = (\"2.XMLHTTP uUBGzxn XulLD XML ream St DONRGsQi AD wItZGAx O qGJR D\").split(\" \");" fullword ascii
    $s4  = "var xopxvJR = \"Sc LeORDep r lZOhsSBYT ipting bEEJqIv LHj ile TdvyFlpNmcYEGh System FV dopHI Obj DnvjOf ect MHcQoST\".split(\" " ascii
    $s5  = "Eiabb.open(hGJSG,qZJXZ,false);" fullword ascii
    $s6  = "if (BXVZm == 793-593){return true;} else {return false;}" fullword ascii
    $s7  = "function yWch(pBcIz) {" fullword ascii
    $s8  = "if (bgdXk > 175187-856){return true;} else {return false;}" fullword ascii
    $s9  = "return dRVzMj.position=904-904;" fullword ascii
    $s10 = "function hYBYTohLv(yuqVuHQfzZR) {" fullword ascii
    $s11 = "function cORC(Eiabb,qZJXZ,hGJSG) {" fullword ascii
    $s12 = "function YQAv(BXVZm) {" fullword ascii
    $s13 = "return luJQ.ExpandEnvironmentStrings(KPhlU);" fullword ascii
    $s14 = "function JTHv(eRAHy) {" fullword ascii
    $s15 = "return eRAHy.status;" fullword ascii
    $s16 = "function lNRzruE(luJQ,KPhlU) {" fullword ascii
    $s17 = "function wtRIRdva() {" fullword ascii
    $s18 = "yLd = m; break; " fullword ascii
    $s19 = "function NOjb(lrLsO) {" fullword ascii
    $s20 = "return Eqvyr;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}