rule sig_20160310_b4982668282c76976c28eaebad4925fe {
  meta:
    description = "datamaliciousorder - file 20160310_b4982668282c76976c28eaebad4925fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e95e39d6e2a6c9cf82dc71da0dcabeb3dd7b3be801334529f6e58f0bf817cf7"

  strings:
    $s1  = "return btkwwlm[0] + btkwwlm[2] + btkwwlm[4] + \".F\" + btkwwlm[7] + btkwwlm[9] + btkwwlm[12] + btkwwlm[14];" fullword ascii
    $s2  = "var Eu = true  , Xdxo = WSC[7] + WSC[9] + WSC[11];" fullword ascii
    $s3  = "var WSC = (\"2.XMLHTTP sCnEGOl iUOCD XML ream St XudiGfys AD TUvOtye O qHyR D\").split(\" \");" fullword ascii
    $s4  = "HTffq.open(OGcIt,cmhwd,false);" fullword ascii
    $s5  = "var btkwwlm = \"Sc rmuunNl r SKgDPYDOs ipting QSiKgRb xGU ile QgNknjNPwynEMW System Bi EnvNL Obj rlYgpJ ect IzQlOTG\".split(\" " ascii
    $s6  = "function LYLE(zkpna,qYmyS) {" fullword ascii
    $s7  = "return lGqz.responseBody;" fullword ascii
    $s8  = "return asvdw.status;" fullword ascii
    $s9  = "function VWfZhQp(lGqz) {" fullword ascii
    $s10 = "function zkQt(rKafj) {" fullword ascii
    $s11 = "function uoFMswYa(IdnoC,XehBpf) {" fullword ascii
    $s12 = "return qeeTHiK(yl,HRYzL[292-286]+HRYzL[974-967]+HRYzL[974-966]);" fullword ascii
    $s13 = "return ERz.size;" fullword ascii
    $s14 = "if (F >= oSHYE.length) {break;}" fullword ascii
    $s15 = "return IkllI;" fullword ascii
    $s16 = "function ynYKb(JEJtzG) {" fullword ascii
    $s17 = "function ywrzk(GPhJqr) {" fullword ascii
    $s18 = "function FHeJXUJr() {" fullword ascii
    $s19 = "return new ActiveXObject(JEJtzG);" fullword ascii
    $s20 = "function qeeTHiK(Gvoa,ckxee) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}