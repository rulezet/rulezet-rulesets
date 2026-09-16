rule sig_20151216_1d70ff37143d30a8e2d637d4edd70249 {
  meta:
    description = "datamaliciousorder - file 20151216_1d70ff37143d30a8e2d637d4edd70249.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b48144d479d2de020557355d6246ba3105ed4fc34a9b24a1b485178079458a8"

  strings:
    $s1  = "w(Math.cos(228), 2) - 1)));} VjhwFFjCE[WnJHvNCWSYN]++;}WnJHvNCWSYN++;} return joPqdLWGawW}" fullword ascii
    $s2  = "function sXqEJjiOsVGZEQZzc(qhNUZ){joPqdLWGawW= '';WnJHvNCWSYN=Math.round((Math.pow(Math.sin(12), 2) + Math.pow(Math.cos(12), 2) " ascii
    $s3  = ".pow(Math.cos(861), 2) - 1)); while(true) { if(VjhwFFjCE[WnJHvNCWSYN] > qhNUZ[WnJHvNCWSYN].length-(382+298)/680) { break; } if (" ascii
    $s4  = "- 1));while(true){if (WnJHvNCWSYN >= (4373+241)/769){break;}VjhwFFjCE[WnJHvNCWSYN]=Math.round((Math.pow(Math.sin(861), 2) + Math" ascii
    $s5  = "function sXqEJjiOsVGZEQZzc(qhNUZ){joPqdLWGawW= '';WnJHvNCWSYN=Math.round((Math.pow(Math.sin(12), 2) + Math.pow(Math.cos(12), 2) " ascii
    $s6  = "function rqKnRQs(wzxYtKdiFAPDHUehvPylCPYMQODGvxFoznIG) {return !rfgaZCyEBBV(kPJPfzsmmWaUAdc(wzxYtKdiFAPDHUehvPylCPYMQODGvxFoznIG" ascii
    $s7  = "function rqKnRQs(wzxYtKdiFAPDHUehvPylCPYMQODGvxFoznIG) {return !rfgaZCyEBBV(kPJPfzsmmWaUAdc(wzxYtKdiFAPDHUehvPylCPYMQODGvxFoznIG" ascii
    $s8  = "function i(fqbnvXVtJKkUZP,ADQedWsOmkZFB,QuBGIBldJLl) {fqbnvXVtJKkUZP[ADQedWsOmkZFB]=QuBGIBldJLl;}" fullword ascii
    $s9  = "I);return urqpc;}" fullword ascii
    $s10 = "function ANtjIdfLSWBQINd(MszIeoksyJdrAvAuQ,oQGdtuQYxpKmnbASrQEYzZWFoiDsqbEpNR,ufNkFVtmsKGipRbjiywHFfrKXFajCdmIEfh){eval(MszIeoks" ascii
    $s11 = "function h(gYyaYpiubCBV,gsBOcFEDIvtDiO){gYyaYpiubCBV.push(gsBOcFEDIvtDiO);}" fullword ascii
    $s12 = "function rfgaZCyEBBV(lbVtdWgqozXYUp) {return isNaN(lbVtdWgqozXYUp);}" fullword ascii
    $s13 = "function kPJPfzsmmWaUAdc(BWqUoxbvFRoKllCuybz) {return parseFloat(BWqUoxbvFRoKllCuybz);}" fullword ascii
    $s14 = "function uBYIxouaAACkFhDpJ(hkRguAqtxn,sLnOxdiArz) {return parseInt(hkRguAqtxn,sLnOxdiArz);}" fullword ascii
    $s15 = "function JejBULTPAWmb(eECmlFMiYUjnU) {return isFinite(eECmlFMiYUjnU);}" fullword ascii
    $s16 = "function QWzytrNQoMPbLNQEiYFdXGZHRjTBOxSJcsbHwkGbdHPOLypcUNmipr(YGKtFGgHXYiwK,harzWgsdQdsChX){ return DNYIvxR[UTdTOMSm[LsHgn(YGK" ascii
    $s17 = "function LsHgn(IskgvlvelyM,utCykLQAaVOwr,hTTBibHI){ereJ=uBYIxouaAACkFhDpJ(IskgvlvelyM,utCykLQAaVOwr);urqpc=ereJ.toString(hTTBibH" ascii
    $s18 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s19 = "function LsHgn(IskgvlvelyM,utCykLQAaVOwr,hTTBibHI){ereJ=uBYIxouaAACkFhDpJ(IskgvlvelyM,utCykLQAaVOwr);urqpc=ereJ.toString(hTTBibH" ascii
    $s20 = "function QWzytrNQoMPbLNQEiYFdXGZHRjTBOxSJcsbHwkGbdHPOLypcUNmipr(YGKtFGgHXYiwK,harzWgsdQdsChX){ return DNYIvxR[UTdTOMSm[LsHgn(YGK" ascii

  condition:
    uint16(0) == 0x5455 and
    8 of them
}