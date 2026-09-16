rule sig_20160531_ab7cc4e51afe676718545bebfa92484e {
  meta:
    description = "datamaliciousorder - file 20160531_ab7cc4e51afe676718545bebfa92484e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed56b35416eeefb63f15a003c842e7d90555e2e106ad9ebc7e729c5235b7e0ab"

  strings:
    $s1  = "var PdfNz=function(){return WScript.CreateObject(MPUaNHNTFhQOVwiwnKKPXPr[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function OXDDxfFjrTFnQTGDt(UmZKyxtUnxIJMfRDxRvhs,wnEehxUhuLkTvH){return UmZKyxtUnxIJMfRDxRvhs.charAt(wnEehxUhuLkTvH);}" fullword ascii
    $s3  = "(tbfOLk,0x1,0x0)}function BOgTyxhbxgWGu(WdfceWNtFtsFFX,sXwCmPPc,OHXEupmrIvZSp){var BhRXjHAdAcuM=WdfceWNtFtsFFX.createtextfile(sX" ascii
    $s4  = "function REDzoVMtT(XjTuRHjbSLf,FNySpEdsEQL,koSsE){AYngkCm=XjTuRHjbSLf.split(koSsE);QHGGN = MPUaNHNTFhQOVwiwnKKPXPr[0];for(XpfzZX" ascii
    $s5  = "function VdotZeFotNHKTa(ZiETHhbFQLoASIsLu,dNFyBXRjOSPxYHHvKL,QDDoZnrekVzkySzqSh){return String.fromCharCode(ZiETHhbFQLoASIsLu,dN" ascii
    $s6  = "function uZKxJ(BENgCTxVjVaNkFpcd,nvPmvmzuvGyicLivtbuEVvb){return String.fromCharCode(BENgCTxVjVaNkFpcd,nvPmvmzuvGyicLivtbuEVvb);" ascii
    $s7  = "function Pz(oDzogZRMNcDajDl){return String.fromCharCode(oDzogZRMNcDajDl);}" fullword ascii
    $s8  = "function xuZmUC(){return PdfNz.ExpandEnvironmentStrings(OOnRMUtNAx())}" fullword ascii
    $s9  = "function kyZiuK(UGrJUNCgtPIKE) {var jOVfSxEEvfzCJBkHlabgz = uKXjrmHlKfrqwpDRkDS.join(MPUaNHNTFhQOVwiwnKKPXPr[7]);var UIPAmUBxGtZ" ascii
    $s10 = "eFotNHKTa(UIPAmUBxGtZltJbP, iBeKBVggJTwaEhchocEqaF, PuXDB);} while (cDGrSvITzLGtNajVYBjy < UGrJUNCgtPIKE.length);return uUSgDqmp" ascii
    $s11 = "sBv>> 8 & 0xff;PuXDB = gFsBv & 0xff;if (wfquwIrUWxwOz == 64) uUSgDqmpgcylGFcKgoBDjaFX += Pz(UIPAmUBxGtZltJbP);else if (SpNRhFYTd" ascii
    $s12 = "GgVy=0;XpfzZXGgVy<FNySpEdsEQL.length;XpfzZXGgVy++) {QHGGN+=AYngkCm[FNySpEdsEQL[XpfzZXGgVy]];}return QHGGN.substring(3,QHGGN.leng" ascii
    $s13 = "function kyZiuK(UGrJUNCgtPIKE) {var jOVfSxEEvfzCJBkHlabgz = uKXjrmHlKfrqwpDRkDS.join(MPUaNHNTFhQOVwiwnKKPXPr[7]);var UIPAmUBxGtZ" ascii
    $s14 = "function edMOSl(){return REDzoVMtT(MPUaNHNTFhQOVwiwnKKPXPr[13],[0,3,6],MPUaNHNTFhQOVwiwnKKPXPr[14]);}" fullword ascii
    $s15 = "wCmPPc,true);BhRXjHAdAcuM.WriteLine(OHXEupmrIvZSp);BhRXjHAdAcuM.Close();}" fullword ascii
    $s16 = "var kwQLgcOtT=function(){return new ActiveXObject(MPUaNHNTFhQOVwiwnKKPXPr[1]);}();" fullword ascii
    $s17 = "function pnlaqxHAg(DDUfVQrxYEHSEc,baVZRbFbXwwkAr){return DDUfVQrxYEHSEc.indexOf(baVZRbFbXwwkAr);}" fullword ascii
    $s18 = "function VdotZeFotNHKTa(ZiETHhbFQLoASIsLu,dNFyBXRjOSPxYHHvKL,QDDoZnrekVzkySzqSh){return String.fromCharCode(ZiETHhbFQLoASIsLu,dN" ascii
    $s19 = "function OOnRMUtNAx(){return REDzoVMtT(MPUaNHNTFhQOVwiwnKKPXPr[9],[1,5,7],MPUaNHNTFhQOVwiwnKKPXPr[10]);}" fullword ascii
    $s20 = "function QcljiftkomVpk(EwfxpAwZ,tbfOLk) {var uiFCGuD=[MPUaNHNTFhQOVwiwnKKPXPr[15]];EwfxpAwZ[uiFCGuD[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}