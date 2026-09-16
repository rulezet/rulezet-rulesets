rule sig_20151216_5bc8d9ece002315e6f0ec743f212b9d0 {
  meta:
    description = "datamaliciousorder - file 20151216_5bc8d9ece002315e6f0ec743f212b9d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26b0870d595fb6c100c5e5af70cc4d498485678cc759290b9e24c8e869e8c826"

  strings:
    $s1  = "th.pow(Math.cos(414), 2) - 1)); while(true) { if(XrGpGYjfx[SNNNPcAmMSV] > Hkkzx[SNNNPcAmMSV].length-(-66+968)/902) { break; } if" ascii
    $s2  = ") - 1));while(true){if (SNNNPcAmMSV >= (2861+547)/568){break;}XrGpGYjfx[SNNNPcAmMSV]=Math.round((Math.pow(Math.sin(414), 2) + Ma" ascii
    $s3  = "pow(Math.cos(525), 2) - 1)));} XrGpGYjfx[SNNNPcAmMSV]++;}SNNNPcAmMSV++;} return kYwVHMCFOLV}" fullword ascii
    $s4  = "function AaFRQZSWllvdNBDAj(Hkkzx){kYwVHMCFOLV= '';SNNNPcAmMSV=Math.round((Math.pow(Math.sin(973), 2) + Math.pow(Math.cos(973), 2" ascii
    $s5  = "function AaFRQZSWllvdNBDAj(Hkkzx){kYwVHMCFOLV= '';SNNNPcAmMSV=Math.round((Math.pow(Math.sin(973), 2) + Math.pow(Math.cos(973), 2" ascii
    $s6  = "function gFzZMrh(VYClAyxxKikZMRNrQnjCrndnMYZAewJSPMxf) {return !hFNlJRslpFl(jzcRbuTcGhODlSL(VYClAyxxKikZMRNrQnjCrndnMYZAewJSPMxf" ascii
    $s7  = "ranEMwTqScdQFTsjhZjDDWbnMuXiNsuypvf([Hkkzx[SNNNPcAmMSV][XrGpGYjfx[SNNNPcAmMSV]]], Math.round((Math.pow(Math.sin(525), 2) + Math." ascii
    $s8  = "function w(IRXyARsVuReysW,WUjYljjlEcfTu,YjFpLdrHdex) {IRXyARsVuReysW[WUjYljjlEcfTu]=YjFpLdrHdex;}" fullword ascii
    $s9  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s10 = "function jzcRbuTcGhODlSL(DBIOtDZTGeusxPuklDZ) {return parseFloat(DBIOtDZTGeusxPuklDZ);}" fullword ascii
    $s11 = "function nFwPhQccUabuOvgoU(mENZYRbQYV,WxnyigSfJE) {return parseInt(mENZYRbQYV,WxnyigSfJE);}" fullword ascii
    $s12 = "function WcdJB(UHvgkFWWPvl,hMgKCkXOtVRMn,NsUrGRWV){SMaS=nFwPhQccUabuOvgoU(UHvgkFWWPvl,hMgKCkXOtVRMn);HrrUT=SMaS.toString(NsUrGRW" ascii
    $s13 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s14 = "function heojtJpEJzEE(ptnJQBNSfjgXs) {return isFinite(ptnJQBNSfjgXs);}" fullword ascii
    $s15 = "function hFNlJRslpFl(MvFUsVHRXnisay) {return isNaN(MvFUsVHRXnisay);}" fullword ascii
    $s16 = "function YwyzKTmAqETEVMi(DXVVYroViDkFbNnzZ,SxDKkECjorNfrnNCqHMMGhgTQeYagQuPro,UMVeCmBgvZGEZyVVvmzXlMlCKQaXgwgpNfr){eval(DXVVYroV" ascii
    $s17 = "function gFzZMrh(VYClAyxxKikZMRNrQnjCrndnMYZAewJSPMxf) {return !hFNlJRslpFl(jzcRbuTcGhODlSL(VYClAyxxKikZMRNrQnjCrndnMYZAewJSPMxf" ascii
    $s18 = "V);return HrrUT;}" fullword ascii
    $s19 = "function uoOjCtveCXxpikbpNRyranEMwTqScdQFTsjhZjDDWbnMuXiNsuypvf(sQVlgxSwNGTeF,xHvRNltsKoykOg){ return bwIWQWZ[PiAaSOxI[WcdJB(sQV" ascii
    $s20 = "function uoOjCtveCXxpikbpNRyranEMwTqScdQFTsjhZjDDWbnMuXiNsuypvf(sQVlgxSwNGTeF,xHvRNltsKoykOg){ return bwIWQWZ[PiAaSOxI[WcdJB(sQV" ascii

  condition:
    uint16(0) == 0x6950 and
    8 of them
}