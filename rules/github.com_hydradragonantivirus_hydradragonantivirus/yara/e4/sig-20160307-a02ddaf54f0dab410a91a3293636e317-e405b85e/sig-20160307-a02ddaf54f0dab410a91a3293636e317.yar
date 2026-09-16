rule sig_20160307_a02ddaf54f0dab410a91a3293636e317 {
  meta:
    description = "datamaliciousorder - file 20160307_a02ddaf54f0dab410a91a3293636e317.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2f8b40529f74e32876687ec9b1a848488bd0c3c2ccc9a12f94ed96bef2ce39b"

  strings:
    $s1  = "var qn = true  , PiqU = eWO[7] + eWO[9] + eWO[11];" fullword ascii
    $s2  = "return nXnOKoG[0] + nXnOKoG[2] + nXnOKoG[4] + \".F\" + nXnOKoG[7] + nXnOKoG[9] + nXnOKoG[12] + nXnOKoG[14];" fullword ascii
    $s3  = "var nXnOKoG = \"Sc hZHnSVj r lszzXsukG ipting zYyYAtV wEf ile EydHXLserQuKXs System mA bGrnd Obj ecyKPL ect MoSoIJc\".split(\" " ascii
    $s4  = "return RUNQ.responseBody;" fullword ascii
    $s5  = "var eWO = (\"2.XMLHTTP ecuVkKW PORWz XML ream St jWPCFZYa AD BJSGqlj O QkUJ D\").split(\" \");" fullword ascii
    $s6  = "DHFAW.open(irYOe,FlHyj,false);" fullword ascii
    $s7  = "function GhxdGve(RUNQ) {" fullword ascii
    $s8  = "function AQZY(LtzbR,qckIt) {" fullword ascii
    $s9  = "function RGmu(DHFAW,FlHyj,irYOe) {" fullword ascii
    $s10 = "function cswb(ZRygT) {" fullword ascii
    $s11 = "function vgpt(iWqjE) {" fullword ascii
    $s12 = "function RSJq(rCypO) {" fullword ascii
    $s13 = "return kqUtToS" fullword ascii
    $s14 = "function fiGj(IheWq) {" fullword ascii
    $s15 = "function bmNkhth(Owxl) {" fullword ascii
    $s16 = "return dHb.size;" fullword ascii
    $s17 = "function QCLV(ghGvy) {" fullword ascii
    $s18 = "function pPUH(DdNvL) {" fullword ascii
    $s19 = "if (IheWq > 168810-907){return true;} else {return false;}" fullword ascii
    $s20 = "return pr.ExpandEnvironmentStrings(VGrFm[6]+VGrFm[7]+VGrFm[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}