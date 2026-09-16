rule sig_20151211_7a857c52f3d814b696187869c01b5680 {
  meta:
    description = "datamaliciousorder - file 20151211_7a857c52f3d814b696187869c01b5680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c880abb323f90ac6cae42b011947243085e32a71268f9d93ceb2fa317cb94c"

  strings:
    $s1  = "function RczOFOM(CyxOnWTTQFsHwjwLZveAwqttKeopBAatHCde) {return !isNaN(parseFloat(CyxOnWTTQFsHwjwLZveAwqttKeopBAatHCde)) && isFin" ascii
    $s2  = "function RczOFOM(CyxOnWTTQFsHwjwLZveAwqttKeopBAatHCde) {return !isNaN(parseFloat(CyxOnWTTQFsHwjwLZveAwqttKeopBAatHCde)) && isFin" ascii
    $s3  = "var h=new Array(\"29\",\"2f\",\"2b\",\"2b\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s4  = "function XKzqsnYLlLLWeQUfd(Udjbo){BdanlOlodQC= '';DPJdrmdfQKT=(-732+732)/984; while(true){if(DPJdrmdfQKT >= (1478+170)/824)break" ascii
    $s5  = ";bHruRkjiH[DPJdrmdfQKT]=(-146+146)/253; while(true) { if(bHruRkjiH[DPJdrmdfQKT] > Udjbo[DPJdrmdfQKT].length-(-412+640)/228) { br" ascii
    $s6  = "T]++;}DPJdrmdfQKT++;} return BdanlOlodQC}" fullword ascii
    $s7  = "function FUXnv(uwuWDJAEGvy,hgaQDTRFXLONH,QXhuAjil){nBro=parseInt(uwuWDJAEGvy,hgaQDTRFXLONH);Ilifi=nBro.toString(QXhuAjil);return" ascii
    $s8  = "function FUXnv(uwuWDJAEGvy,hgaQDTRFXLONH,QXhuAjil){nBro=parseInt(uwuWDJAEGvy,hgaQDTRFXLONH);Ilifi=nBro.toString(QXhuAjil);return" ascii
    $s9  = "function zIkxbQsjbFuWYUBSdBFpEhpJqYWgKFLsEeLarwVhXzmjWcDklXJsTQ(jKyJhqLnwjgtM,BHYzwZocnzLcZn){ return olWfG[FUXnv(jKyJhqLnwjgtM[" ascii
    $s10 = "function RcuHxUXlXAM(RkAAuIaH,aSFQcK){return RkAAuIaH.split(aSFQcK)}" fullword ascii
    $s11 = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"46\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function zIkxbQsjbFuWYUBSdBFpEhpJqYWgKFLsEeLarwVhXzmjWcDklXJsTQ(jKyJhqLnwjgtM,BHYzwZocnzLcZn){ return olWfG[FUXnv(jKyJhqLnwjgtM[" ascii
    $s13 = "function XKzqsnYLlLLWeQUfd(Udjbo){BdanlOlodQC= '';DPJdrmdfQKT=(-732+732)/984; while(true){if(DPJdrmdfQKT >= (1478+170)/824)break" ascii
    $s14 = "var h=new Array(\"29\",\"2f\",\"2b\",\"2b\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s15 = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"46\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = " Ilifi;}function qPaJQGimbipbVah(IxIIBrPNSRhNwORJf){eval(IxIIBrPNSRhNwORJf)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}