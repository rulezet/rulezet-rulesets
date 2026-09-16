rule sig_20160303_a8a6851c1e9d7a3781a13002032ccade {
  meta:
    description = "datamaliciousorder - file 20160303_a8a6851c1e9d7a3781a13002032ccade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98fd420806035eafd3e770448ceff8691b898979b293f52701d4962eb2f7efaa"

  strings:
    $s1  = "var jE = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(fmMvU);" fullword ascii
    $s3  = "function ISpY(fmMvU) {" fullword ascii
    $s4  = "var UCQ = (zhx + \"TTP\" + \" NgKfmqH BzzRs XML ream St nhZqoJPE AD VXXoBaI OD\").split(\" \");" fullword ascii
    $s5  = "var jJ = true  , pcEm = UCQ[7] + \"\" + UCQ[9];" fullword ascii
    $s6  = "return \"Sc\" + \"r\" + PfomYIv + \".F\" + GncNnFdwSt + bjUuV + \"Obj\" + \"ect\";" fullword ascii
    $s7  = "pzREU.open(IDVpt,SWmZv,false);" fullword ascii
    $s8  = "function ohtg(VWWKS) {" fullword ascii
    $s9  = "function ifTgixOU() {" fullword ascii
    $s10 = "function vFTtVbn(jiKH) {" fullword ascii
    $s11 = "if (VWWKS == 1162-962){return true;} else {return false;}" fullword ascii
    $s12 = "function bcRRk(TNskuw) {" fullword ascii
    $s13 = "function utqf(DryHh,GvkpJ) {" fullword ascii
    $s14 = "if (((new Date())>0,7157646888)) {" fullword ascii
    $s15 = "function QCes(ldFjc) {" fullword ascii
    $s16 = "function TKHw(bDaMp) {" fullword ascii
    $s17 = "XrN = a; break; " fullword ascii
    $s18 = "function SBJf(IxkIK) {" fullword ascii
    $s19 = "return ce.ExpandEnvironmentStrings(jE);" fullword ascii
    $s20 = "function vQCe(pzREU,SWmZv,IDVpt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}