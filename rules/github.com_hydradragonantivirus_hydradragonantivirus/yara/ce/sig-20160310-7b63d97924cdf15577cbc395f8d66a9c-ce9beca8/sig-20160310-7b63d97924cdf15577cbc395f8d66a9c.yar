rule sig_20160310_7b63d97924cdf15577cbc395f8d66a9c {
  meta:
    description = "datamaliciousorder - file 20160310_7b63d97924cdf15577cbc395f8d66a9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8adcd535c1018bb98e490ac81d33c4b906270bf82a8612c40d38a1c4fc224bac"

  strings:
    $s1  = "var Dw = true  , dHpm = kdK[7] + kdK[9] + kdK[11];" fullword ascii
    $s2  = "return SMKnlYx[0] + SMKnlYx[2] + SMKnlYx[4] + \".F\" + SMKnlYx[7] + SMKnlYx[9] + SMKnlYx[12] + SMKnlYx[14];" fullword ascii
    $s3  = "var kdK = (\"2.XMLHTTP VevuOBt sDTFm XML ream St aKOgQYwS AD EnIQPsp O FOgM D\").split(\" \");" fullword ascii
    $s4  = "AXmor.open(wlgrm,EDeGL,false);" fullword ascii
    $s5  = "var SMKnlYx = \"Sc jzqgtpi r sINOZsvXu ipting dcORrWf Iqg ile SmVYooZJVpmNVC System ko DKQcV Obj drobWW ect PUUtaIz\".split(\" " ascii
    $s6  = "if(y>=U.length) {break;}" fullword ascii
    $s7  = "function JtSs(wEclD,RMSWb) {" fullword ascii
    $s8  = "function YFNj(wMnbr) {" fullword ascii
    $s9  = "function TlaqsNeFR(FXoCBebCIQb) {" fullword ascii
    $s10 = "function jAkx(vQHJN) {" fullword ascii
    $s11 = "return LXFY.ExpandEnvironmentStrings(IALxG);" fullword ascii
    $s12 = "return nUC.size;" fullword ascii
    $s13 = "function rSjUrKdB(WtATE,bnzIfX) {" fullword ascii
    $s14 = "function mbnOapi(OsRW) {" fullword ascii
    $s15 = "function dFeI(HZuyU,vRUjt) {" fullword ascii
    $s16 = "function iPwq(blxhn) {" fullword ascii
    $s17 = "function pDHd(CiOnO) {" fullword ascii
    $s18 = "function pURNxsR(LXFY,IALxG) {" fullword ascii
    $s19 = "Mww = y; break; " fullword ascii
    $s20 = "function lCzk(OuDqX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}