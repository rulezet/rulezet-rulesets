rule sig_20160303_4e0c1277122b8a473260129f70e5f1d5 {
  meta:
    description = "datamaliciousorder - file 20160303_4e0c1277122b8a473260129f70e5f1d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09872728c7c8f043d7dd7b4a96c12be359a41eabe90e5dd28a3c8b76702692f6"

  strings:
    $s1  = "var HM = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(VRcfh);" fullword ascii
    $s3  = "var ec = true  , clmE = rMl[7] + \"\" + rMl[9];" fullword ascii
    $s4  = "var rMl = (rFM + \"TTP\" + \" fesuIIU nkOEW XML ream St kfZIBquq AD hBgrJAA OD\").split(\" \");" fullword ascii
    $s5  = "AaWay.open(haGgc,XOwyG,false);" fullword ascii
    $s6  = "if (UfycV == 777-577){return true;} else {return false;}" fullword ascii
    $s7  = "function kztbYjHd() {" fullword ascii
    $s8  = "function tzheyfaiV(ObOJRYWocnA) {" fullword ascii
    $s9  = "if (((new Date())>0,7119915888)) {" fullword ascii
    $s10 = "return xU.ExpandEnvironmentStrings(HM);" fullword ascii
    $s11 = "function ahku(hfvTb,Ffboz) {" fullword ascii
    $s12 = "return hudEK.status;" fullword ascii
    $s13 = "return new ActiveXObject(EWmuDb);" fullword ascii
    $s14 = "function KDiV(hudEK) {" fullword ascii
    $s15 = "function LqHD(VRcfh) {" fullword ascii
    $s16 = "if(S>=R.length) {break;}" fullword ascii
    $s17 = "wmI = S; break; " fullword ascii
    $s18 = "function uhEw(kVloJ) {" fullword ascii
    $s19 = "function iqte(mpebh) {" fullword ascii
    $s20 = "return \"Sc\" + \"r\" + yGxhLuM + \".F\" + ccRTRBYLJH + CaYYY + \"Obj\" + \"ect\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}