rule sig_20160324_12e078ab72366279270d283fc583b172 {
  meta:
    description = "datamaliciousorder - file 20160324_12e078ab72366279270d283fc583b172.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e25c9c9db8ce02dd17c195e47730439976407f252ff6dc8124f718d777300f0"

  strings:
    $s1  = "return WScript.CreateObject(gsJTw);" fullword ascii
    $s2  = "var uw = true  , nhgz = GGg[7] + GGg[9] + GGg[11];" fullword ascii
    $s3  = "return szvokZi[0] + szvokZi[2] + szvokZi[4] + \".F\" + szvokZi[7] + szvokZi[9] + szvokZi[12] + szvokZi[14];" fullword ascii
    $s4  = "waxL.open(OGJIS,CrurK,false);" fullword ascii
    $s5  = "var GGg = (\"2.XMLHTTP lbBmgNu kVjlT XML ream St rqRxdHHG AD RaCRuMn O GOii D\").split(\" \");" fullword ascii
    $s6  = "var szvokZi = DEKRx(SiPBUvOnzk+\" \"+\"System Kq aqCQF Obj JIFeMm ect zHoXlcU fxVdF\", \" \");" fullword ascii
    $s7  = "if(S>=N.length) {break;}" fullword ascii
    $s8  = "function FgtA(oCrHM) {" fullword ascii
    $s9  = "return new ActiveXObject(bmcR);" fullword ascii
    $s10 = "if (FGQMn > 177740-501){return true;} else {return false;}" fullword ascii
    $s11 = "return mUhwnF/*7nUVsiCfFZm6YaZDcnXY2l9YP*/.position=604-604;" fullword ascii
    $s12 = "Aae = S; break; " fullword ascii
    $s13 = "if (oCrHM == 427-227){return true;} else {return false;}" fullword ascii
    $s14 = "function LJiY(FGQMn) {" fullword ascii
    $s15 = "var pfaipof = \"Pinqnn*DEs*pt.S\"+\"hell*xTfLJxH*Scri*\";" fullword ascii
    $s16 = "function qjSbyUZu(mLf) {" fullword ascii
    $s17 = "function LJkjX(ilAfZXZv,fRwS) {" fullword ascii
    $s18 = "function EdzK(gsJTw) {" fullword ascii
    $s19 = "return lcNG.ExpandEnvironmentStrings(SQYYk);" fullword ascii
    $s20 = "return mLf.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}