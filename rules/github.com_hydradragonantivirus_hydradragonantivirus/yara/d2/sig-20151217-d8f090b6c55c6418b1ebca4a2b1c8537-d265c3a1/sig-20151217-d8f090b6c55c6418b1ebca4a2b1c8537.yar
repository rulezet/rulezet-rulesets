rule sig_20151217_d8f090b6c55c6418b1ebca4a2b1c8537 {
  meta:
    description = "datamaliciousorder - file 20151217_d8f090b6c55c6418b1ebca4a2b1c8537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4822a688693bc709debd6afa3a383df77f4c203a23d4581190daef512eead792"

  strings:
    $s1  = ") - 1));while(true){if (HSUCFeCwyux >= (3126+708)/639){break;}CYdahJASO[HSUCFeCwyux]=Math.round((Math.pow(Math.sin(166), 2) + Ma" ascii
    $s2  = "function posdLYuGeAVTOCbeM(BTrJX){swLsvBKFNen= '';HSUCFeCwyux=Math.round((Math.pow(Math.sin(704), 2) + Math.pow(Math.cos(704), 2" ascii
    $s3  = ".pow(Math.cos(203), 2) - 1)));} CYdahJASO[HSUCFeCwyux]++;}HSUCFeCwyux++;} return swLsvBKFNen}" fullword ascii
    $s4  = "th.pow(Math.cos(166), 2) - 1)); while(true) { if(CYdahJASO[HSUCFeCwyux] > BTrJX[HSUCFeCwyux].length-(-175+981)/806) { break; } i" ascii
    $s5  = "function posdLYuGeAVTOCbeM(BTrJX){swLsvBKFNen= '';HSUCFeCwyux=Math.round((Math.pow(Math.sin(704), 2) + Math.pow(Math.cos(704), 2" ascii
    $s6  = "QAVvVsvuTdngomjJCIoqrTOtLMRoMwevaFxs([BTrJX[HSUCFeCwyux][CYdahJASO[HSUCFeCwyux]]], Math.round((Math.pow(Math.sin(203), 2) + Math" ascii
    $s7  = "function sbhIVsD(sUBgVHWIgqaxEonrNbLbcjjnjWoIVhhAAPeW) {return !jnInYztKjFt(JsRJwdNAzVeWeMt(sUBgVHWIgqaxEonrNbLbcjjnjWoIVhhAAPeW" ascii
    $s8  = "u);return lyIWD;}" fullword ascii
    $s9  = "function DzxaZBmnZuCL(ktLKsYPaLrpbm) {return isFinite(ktLKsYPaLrpbm);}" fullword ascii
    $s10 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s11 = "function VMvlAxiilHrhVbqBsYQAVvVsvuTdngomjJCIoqrTOtLMRoMwevaFxs(NjvxoejmDHMla,mcjciybeLGgBuW){ return iyGFKWo[lMNjETse[WBGjx(Njv" ascii
    $s12 = "function sbhIVsD(sUBgVHWIgqaxEonrNbLbcjjnjWoIVhhAAPeW) {return !jnInYztKjFt(JsRJwdNAzVeWeMt(sUBgVHWIgqaxEonrNbLbcjjnjWoIVhhAAPeW" ascii
    $s13 = "function W(SoKxAncibrMnRz,SpapObzrLNWgf,mnZyoupicQn) {SoKxAncibrMnRz[SpapObzrLNWgf]=mnZyoupicQn;}" fullword ascii
    $s14 = "function JsRJwdNAzVeWeMt(MwtRrnGTMOIuITivuKQ) {return parseFloat(MwtRrnGTMOIuITivuKQ);}" fullword ascii
    $s15 = "function WBGjx(PRDwTnvJfZc,erXBxDZyNnmUa,kRnMYOFu){hiXg=OPVKpagpZusCExgZc(PRDwTnvJfZc,erXBxDZyNnmUa);lyIWD=hiXg.toString(kRnMYOF" ascii
    $s16 = "function OGhPeDaNmBAWaFD(dzBycnUNbZzPLSfWU,yezTIDvFytmuMmfPqYxAnjZzmruaMhOKLV,wibStKRtDGroNzErtIvkZxTnEPYwpFzYNBE){eval(dzBycnUN" ascii
    $s17 = "function WBGjx(PRDwTnvJfZc,erXBxDZyNnmUa,kRnMYOFu){hiXg=OPVKpagpZusCExgZc(PRDwTnvJfZc,erXBxDZyNnmUa);lyIWD=hiXg.toString(kRnMYOF" ascii
    $s18 = "function OPVKpagpZusCExgZc(EnhtoOASJS,jHognjguYY) {return parseInt(EnhtoOASJS,jHognjguYY);}" fullword ascii
    $s19 = "function jnInYztKjFt(sgGjkTMeLXzTZb) {return isNaN(sgGjkTMeLXzTZb);}" fullword ascii
    $s20 = "function OGhPeDaNmBAWaFD(dzBycnUNbZzPLSfWU,yezTIDvFytmuMmfPqYxAnjZzmruaMhOKLV,wibStKRtDGroNzErtIvkZxTnEPYwpFzYNBE){eval(dzBycnUN" ascii

  condition:
    uint16(0) == 0x4d6c and
    8 of them
}