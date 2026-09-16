rule sig_20160309_9e085d84bdfb52d119cab77b4989b4d2 {
  meta:
    description = "datamaliciousorder - file 20160309_9e085d84bdfb52d119cab77b4989b4d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "082c5eaf099fd5a4d5271a0202f4f7d38e048bb1c8b055dd6bef0d13d4381a79"

  strings:
    $s1  = "var Nu = true  , xfUP = Ggf[7] + Ggf[9] + Ggf[11];" fullword ascii
    $s2  = "return YtaZyeo[0] + YtaZyeo[2] + YtaZyeo[4] + \".F\" + YtaZyeo[7] + YtaZyeo[9] + YtaZyeo[12] + YtaZyeo[14];" fullword ascii
    $s3  = "var Ggf = (\"2.XMLHTTP HUXKspu eAWwD XML ream St TAqYUvyI AD hJQkhyB O ZPdV D\").split(\" \");" fullword ascii
    $s4  = "var YtaZyeo = \"Sc zKveIFR r xgMVabPmP ipting SNEGVuN wZt ile idJPCPpUQuHMtO System XD MJDNk Obj FHiSUp ect ndxMBLm\".split(\" " ascii
    $s5  = "GSrXW.open(LProC,lRGOI,false);" fullword ascii
    $s6  = "function ECGG(jIQCc) {" fullword ascii
    $s7  = "function pTkYiEJGn(Odatx,ngFLV,VibXN,LanG) {" fullword ascii
    $s8  = "function WgiPpir(HsnS,ktZSu) {" fullword ascii
    $s9  = "return WgiPpir(fr,oHaQo[380-374]+oHaQo[845-838]+oHaQo[747-739]);" fullword ascii
    $s10 = "return MxlrwgY" fullword ascii
    $s11 = "asU = j; break; " fullword ascii
    $s12 = "function hphc(lQRBt) {" fullword ascii
    $s13 = "function hHPj(GJKsD) {" fullword ascii
    $s14 = "function oMJmHWXJ(CPUJI,BymJfv) {" fullword ascii
    $s15 = "return new ActiveXObject(JMUoHA);" fullword ascii
    $s16 = "return HsnS.ExpandEnvironmentStrings(ktZSu);" fullword ascii
    $s17 = "function ZAdR(hdtXX) {" fullword ascii
    $s18 = "function mWAX(kgxhM,sEmdA) {" fullword ascii
    $s19 = "function sUQo(mDBIu) {" fullword ascii
    $s20 = "function cQoXt(JMUoHA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}