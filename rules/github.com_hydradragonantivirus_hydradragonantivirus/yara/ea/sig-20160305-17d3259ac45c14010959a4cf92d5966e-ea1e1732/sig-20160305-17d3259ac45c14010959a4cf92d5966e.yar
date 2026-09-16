rule sig_20160305_17d3259ac45c14010959a4cf92d5966e {
  meta:
    description = "datamaliciousorder - file 20160305_17d3259ac45c14010959a4cf92d5966e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67215050fe5045f580fb4d2397cdd88b84ea3e9264355556833e6a129eb26381"

  strings:
    $s1  = "var PNcoT = \"SinkyO PKi pt.Shell vSjidgZ Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return uQrVJGj[0] + uQrVJGj[2] + uQrVJGj[4] + \".F\" + uQrVJGj[7] + uQrVJGj[9] + uQrVJGj[12] + uQrVJGj[14];" fullword ascii
    $s3  = "var mJ = true  , HFzX = wCR[7] + \"\" + wCR[9];" fullword ascii
    $s4  = "var wCR = (vPY + \"TTP\" + \" gaGrWlL PqSyP XML ream St YlYqUqjf AD uVMXxLF OD\").split(\" \");" fullword ascii
    $s5  = "ZLJTh.open(JjOXg,gbGZQ,false);" fullword ascii
    $s6  = "var uQrVJGj = \"Sc tSppmkq r nszAJsDCr ipting pAPVggQ qPO ile XxkDeLKqNeatOa System KU ESRAu Obj tXYpGe ect PzfSwar\".split(\" " ascii
    $s7  = "function WDnd(nCttS,VViWF) {" fullword ascii
    $s8  = "if(S>=O.length) {break;}" fullword ascii
    $s9  = "function zoPR(HVdqg) {" fullword ascii
    $s10 = "if (DZxiI > 192163-283){return true;} else {return false;}" fullword ascii
    $s11 = "return iNZJ.responseBody;" fullword ascii
    $s12 = "if (((new Date())>0,7846097888)) {" fullword ascii
    $s13 = "Jjx = S; break; " fullword ascii
    $s14 = "return oh.ExpandEnvironmentStrings(PNcoT[6]);" fullword ascii
    $s15 = "if (fTiOq == 1073-873){return true;} else {return false;}" fullword ascii
    $s16 = "function HmtfXyf(iNZJ) {" fullword ascii
    $s17 = "function JPHM(qyuzV) {" fullword ascii
    $s18 = "function kbSY(VrsUH) {" fullword ascii
    $s19 = "function GVDFDLRaG(FdoMmxeBVXa) {" fullword ascii
    $s20 = "function NyAGK(sIPjfw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}