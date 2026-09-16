rule sig_20160303_e0c77f3c0360f9bb6f522f5a8b3a07ad {
  meta:
    description = "datamaliciousorder - file 20160303_e0c77f3c0360f9bb6f522f5a8b3a07ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "934a5409d63849f7bdbb274afc883ec13187962901c3a7dcbfb96a0f99e8089f"

  strings:
    $s1  = "var gQnId = \"VLnnyL Wdg pt.Shell NCZKzaH Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "function wlmPQyoxQ(NqhSPYlDveE) {" fullword ascii
    $s3  = "return TpegXPh[0] + TpegXPh[2] + TpegXPh[4] + \".F\" + TpegXPh[7] + TpegXPh[9] + TpegXPh[12] + TpegXPh[14];" fullword ascii
    $s4  = "var gpp = (gmb + \"TTP\" + \" hwyoBLg kNiUg XML ream St SIDFMnqL AD ioaazcz OD\").split(\" \");" fullword ascii
    $s5  = "var DB = true  , uXer = gpp[7] + \"\" + gpp[9];" fullword ascii
    $s6  = "SzwtZ.open(mTODj,pIJig,false);" fullword ascii
    $s7  = "var TpegXPh = \"Sc RfWclzC r IunjCJjSf ipting GyKZLRI XvD ile zfOCHreLwQNBpB System zn pMCMS Obj hMlJVb ect NalErny\".split(\" " ascii
    $s8  = "if(h>=E.length) {break;}" fullword ascii
    $s9  = "if (((new Date())>0,746460888)) {" fullword ascii
    $s10 = "function qfPs(RsdiF) {" fullword ascii
    $s11 = "function rLif(GeiJW) {" fullword ascii
    $s12 = "function OuFo(ruyZp) {" fullword ascii
    $s13 = "function hkhw(rnmAT) {" fullword ascii
    $s14 = "function cRFC(BLSNk) {" fullword ascii
    $s15 = "return AiwZP;" fullword ascii
    $s16 = "if (ruyZp == 560-360){return true;} else {return false;}" fullword ascii
    $s17 = "function bbjC(qcFLq,rpttW) {" fullword ascii
    $s18 = "return jcLQ.responseBody;" fullword ascii
    $s19 = "function midnFDGm() {" fullword ascii
    $s20 = "return ujAzSbT" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}