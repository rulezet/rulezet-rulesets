rule sig_20160314_cd1e191ca2579951d2b681278dde5d9c {
  meta:
    description = "datamaliciousorder - file 20160314_cd1e191ca2579951d2b681278dde5d9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "329c01f915634bb7f173028bfeb1738b069a84a4a7f639ff7637223404674d7f"

  strings:
    $s1  = "return HKCkrmh[0] + HKCkrmh[2] + HKCkrmh[4] + \".F\" + HKCkrmh[7] + HKCkrmh[9] + HKCkrmh[12] + HKCkrmh[14];" fullword ascii
    $s2  = "var gU = true  , qhoZ = poT[7] + poT[9] + poT[11];" fullword ascii
    $s3  = "JghjW.open(WniSg,amlNt,false);" fullword ascii
    $s4  = "var poT = (\"2.XMLHTTP hFXgqsP WZeGz XML ream St xqzaNPNr AD zdxcwfp O jhVw D\").split(\" \");" fullword ascii
    $s5  = "var HKCkrmh = \"Sc kdoMRjn r imVXSMBLu ipting uxxskPO oBW ile JJjVgzmyzECrxP System IN ImqZA Obj ZouTim ect diEfPVJ keJiG\".spli" ascii
    $s6  = "var HKCkrmh = \"Sc kdoMRjn r imVXSMBLu ipting uxxskPO oBW ile JJjVgzmyzECrxP System IN ImqZA Obj ZouTim ect diEfPVJ keJiG\".spli" ascii
    $s7  = "if(t>=w.length) {break;}" fullword ascii
    $s8  = "function bMpw(EnjRr) {" fullword ascii
    $s9  = "return jmsg.ExpandEnvironmentStrings(eQetz);" fullword ascii
    $s10 = "return yLFsBpX(iM,wJgSi[641-635]+wJgSi[428-421]+wJgSi[948-940]);" fullword ascii
    $s11 = "function tpjl(JghjW,amlNt,WniSg) {" fullword ascii
    $s12 = "return sbpIKPD" fullword ascii
    $s13 = "return new ActiveXObject(hCwJZu);" fullword ascii
    $s14 = "function JbSz(EPNmI) {" fullword ascii
    $s15 = "return JTfRc;" fullword ascii
    $s16 = "function igCls(hCwJZu) {" fullword ascii
    $s17 = "function fMIp(ZfJrx) {" fullword ascii
    $s18 = "function nMrX(Hsmdd,qYJAH) {" fullword ascii
    $s19 = "function XTSiEItT() {" fullword ascii
    $s20 = "function ExqtQukPl(esssZZdtgBL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}