rule sig_20160310_f6dc34ec249bdfed0b6c36e15a2fb221 {
  meta:
    description = "datamaliciousorder - file 20160310_f6dc34ec249bdfed0b6c36e15a2fb221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed55c5e5dccd87eadafbe29c78aa900cea46211b05b5ea524fe697e644302ffa"

  strings:
    $s1  = "var lJ = true  , yoHK = mYh[7] + mYh[9] + mYh[11];" fullword ascii
    $s2  = "return TmeECUY[0] + TmeECUY[2] + TmeECUY[4] + \".F\" + TmeECUY[7] + TmeECUY[9] + TmeECUY[12] + TmeECUY[14];" fullword ascii
    $s3  = "var TmeECUY = \"Sc sEIJYvH r iSWZdhsLX ipting YDgGjox RMU ile mPTumhHmpOtWkg System bq LzrSX Obj KPqkhe ect hxVkDIA\".split(\" " ascii
    $s4  = "JkYOi.open(gpkgh,IwOYR,false);" fullword ascii
    $s5  = "var mYh = (\"2.XMLHTTP HAYlJcj eIVvt XML ream St VffHfVty AD LQjfbBz O NsEI D\").split(\" \");" fullword ascii
    $s6  = "function RtCglEP(fpKV) {" fullword ascii
    $s7  = "function ETJi(zvQgY) {" fullword ascii
    $s8  = "if (dQIeB == 544-344){return true;} else {return false;}" fullword ascii
    $s9  = "if (wNUbT > 191014-383){return true;} else {return false;}" fullword ascii
    $s10 = "function zVsmGPvl(cKW) {" fullword ascii
    $s11 = "function AZHSNSiYB(dTtMLcmKniq) {" fullword ascii
    $s12 = "function pMFQj(jdQzQZ) {" fullword ascii
    $s13 = "function kfsCiobU(xxpdb,cxYIax) {" fullword ascii
    $s14 = "function TpZjSEBU() {" fullword ascii
    $s15 = "function TRJi(wNUbT) {" fullword ascii
    $s16 = "function uqrG(ZDrCH) {" fullword ascii
    $s17 = "function RvmOydU(lAnt,IVBlT) {" fullword ascii
    $s18 = "return roAYNSC" fullword ascii
    $s19 = "Qhg = q; break; " fullword ascii
    $s20 = "function VoDh(JkYOi,IwOYR,gpkgh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}