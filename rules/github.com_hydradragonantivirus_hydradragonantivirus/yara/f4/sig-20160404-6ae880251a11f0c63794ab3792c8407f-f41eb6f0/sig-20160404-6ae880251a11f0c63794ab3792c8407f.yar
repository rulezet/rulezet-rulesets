rule sig_20160404_6ae880251a11f0c63794ab3792c8407f {
  meta:
    description = "datamaliciousorder - file 20160404_6ae880251a11f0c63794ab3792c8407f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c4b25b40cb6a750564279e6536a7fa274904c575ed62dc3d72ee53a2e4bd23d"

  strings:
    $s1  = "function oTyjgetP(ySyR) {" fullword ascii
    $s2  = "return TkPkoLb[0] + TkPkoLb[2] + TkPkoLb[4] + \".F\" + TkPkoLb[7] + TkPkoLb[9] + TkPkoLb[12] + TkPkoLb[14];" fullword ascii
    $s3  = "var WP = true  , MTip = RUd[7] + RUd[9] + RUd[11];" fullword ascii
    $s4  = "exkr.open(wjFMs,OCmjv,false);" fullword ascii
    $s5  = "var RUd = (\"2.XMLHTTP uVVAWDG cZihy XML ream St auiTSSBk AD rxjtpDF O puwf D\").split(\" \");" fullword ascii
    $s6  = "var TkPkoLb = oXkBu(UACzPkuQuq+\" \"+\"System Jv pRPxz Obj YFAIhT ect OhnKlYQ mKMZL\", \" \");" fullword ascii
    $s7  = "function oiFP(XjeTE,Vjjju) {" fullword ascii
    $s8  = "function pojRBU(aVey,yTCxEn) {" fullword ascii
    $s9  = "function XdsX(gecrz,OCmjv,wjFMs) {" fullword ascii
    $s10 = "function LNTx(vyUoB) {" fullword ascii
    $s11 = "function QXmf(BgHQH,cSRVA) {" fullword ascii
    $s12 = "return vyUoB.status;" fullword ascii
    $s13 = "function WbZQCl(PbxehQW) {" fullword ascii
    $s14 = "if (RraQh > 159242-514){return true;} else {return false;}" fullword ascii
    $s15 = "function KOtg(YLuBg) {" fullword ascii
    $s16 = "function Pbqu(cIOUO) {" fullword ascii
    $s17 = "return new ActiveXObject(eGaU);" fullword ascii
    $s18 = "return fWku;" fullword ascii
    $s19 = "if(z>=U.length) {break;}" fullword ascii
    $s20 = "function DuHNcRr(skde,YvEYI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}