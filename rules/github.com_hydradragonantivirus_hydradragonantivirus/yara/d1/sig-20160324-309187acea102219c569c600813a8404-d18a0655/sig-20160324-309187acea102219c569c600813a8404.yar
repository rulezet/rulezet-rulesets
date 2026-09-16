rule sig_20160324_309187acea102219c569c600813a8404 {
  meta:
    description = "datamaliciousorder - file 20160324_309187acea102219c569c600813a8404.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0ada1856362b3b8fee8b79e3c95d702b19374d638ea53b2ca0a2650791526f0"

  strings:
    $s1  = "return WScript.CreateObject(nWzUm);" fullword ascii
    $s2  = "return qKNszMX[0] + qKNszMX[2] + qKNszMX[4] + \".F\" + qKNszMX[7] + qKNszMX[9] + qKNszMX[12] + qKNszMX[14];" fullword ascii
    $s3  = "var Zc = true  , bRgU = ntZ[7] + ntZ[9] + ntZ[11];" fullword ascii
    $s4  = "var ntZ = (\"2.XMLHTTP LcUMXGm rVehe XML ream St IUFYFgYH AD hkStOXU O mSvI D\").split(\" \");" fullword ascii
    $s5  = "Ugzp.open(iqExu,ZKwLJ,false);" fullword ascii
    $s6  = "var qKNszMX = gQiRT(yjxhSStpHb+\" \"+\"System eb MDQIs Obj jcIBbg ect QfcVkhg yQFrG\", \" \");" fullword ascii
    $s7  = "if (U >= swJjx.length) {break;}" fullword ascii
    $s8  = "function nplqR(cgnLFV) {" fullword ascii
    $s9  = "var IrYVWJs = \"XKuvtI*qqt*pt.S\"+\"hell*SpohCvR*Scri*\";" fullword ascii
    $s10 = "function edtxsxOCX(ewpmA) {" fullword ascii
    $s11 = "function VZpXqzBV(urWu) {" fullword ascii
    $s12 = "function KVUn(mLtta,ZKwLJ,iqExu) {" fullword ascii
    $s13 = "function dklh(uTaFD) {" fullword ascii
    $s14 = "return new ActiveXObject(qIds);" fullword ascii
    $s15 = "function BqEocRMX(VEr) {" fullword ascii
    $s16 = "function uCMY(nWzUm) {" fullword ascii
    $s17 = "uKG = D; break; " fullword ascii
    $s18 = "function jXtB(CsWzj) {" fullword ascii
    $s19 = "function RoBz(GxOsN) {" fullword ascii
    $s20 = "function PeaU(EseiJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}