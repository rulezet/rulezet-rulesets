rule sig_20160302_31e2ef22feacc7c40aace4783540dc94 {
  meta:
    description = "datamaliciousorder - file 20160302_31e2ef22feacc7c40aace4783540dc94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f794d1313cc4f89f6b019dd1c992c7eaeb9ec1e1e2895b931261231ae3f283"

  strings:
    $s1  = "var Lz = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(PVvXT);" fullword ascii
    $s3  = "var KE = true  , rxLF = IJd[7] + \"\" + IJd[9];" fullword ascii
    $s4  = "var IJd = (YIh + \"TTP\" + \" GDENBJp CmaSX XML ream St jtpkhyon AD pwDkzAe OD\").split(\" \");" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + zXuHBkQ + \".F\" + JBIizAoGDq + yahRn + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "VXsBK.open(yBUFu,SCYFs,false);" fullword ascii
    $s7  = "qJW = w; break; " fullword ascii
    $s8  = "if (((new Date())>0,7677091888)) {" fullword ascii
    $s9  = "function ozBeJHHoV(svyirKJVaZO) {" fullword ascii
    $s10 = "MOwn(yBD); yBD.type = 1; dpXl(yBD,by.responseBody); if (wcrD(yBD.size))  {" fullword ascii
    $s11 = "function yZfvd(nYiuNA) {" fullword ascii
    $s12 = "function kDvYPigW() {" fullword ascii
    $s13 = "if(w>=f.length) {break;}" fullword ascii
    $s14 = "if (yhgfU > 163384-914){return true;} else {return false;}" fullword ascii
    $s15 = "if (ODyWE == 368-168){return true;} else {return false;}" fullword ascii
    $s16 = "function pfln(GYyYb) {" fullword ascii
    $s17 = "return new ActiveXObject(nYiuNA);" fullword ascii
    $s18 = "function PgoJ(ODyWE) {" fullword ascii
    $s19 = "function pFmz(vCgUm) {" fullword ascii
    $s20 = "function GNDv(PVvXT) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}