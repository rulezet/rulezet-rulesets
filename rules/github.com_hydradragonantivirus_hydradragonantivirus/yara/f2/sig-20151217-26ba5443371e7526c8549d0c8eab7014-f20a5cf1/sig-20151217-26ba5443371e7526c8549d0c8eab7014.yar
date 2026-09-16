rule sig_20151217_26ba5443371e7526c8549d0c8eab7014 {
  meta:
    description = "datamaliciousorder - file 20151217_26ba5443371e7526c8549d0c8eab7014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0029f261b646d22cbd46f419f805a4e2331b3f20d30bbe88756de655ed1b8ebc"

  strings:
    $s1  = "th.pow(Math.cos(812), 2) - 1)); while(true) { if(pDGxPGCOC[uhzjWfecHGT] > AaRMW[uhzjWfecHGT].length-(15+230)/245) { break; } if " ascii
    $s2  = ") - 1));while(true){if (uhzjWfecHGT >= (3556+104)/610){break;}pDGxPGCOC[uhzjWfecHGT]=Math.round((Math.pow(Math.sin(812), 2) + Ma" ascii
    $s3  = "Math.cos(837), 2) - 1)));} pDGxPGCOC[uhzjWfecHGT]++;}uhzjWfecHGT++;} return ssVfKmGpjCA}" fullword ascii
    $s4  = "function JRuejarxvVKYsCvfz(AaRMW){ssVfKmGpjCA= '';uhzjWfecHGT=Math.round((Math.pow(Math.sin(123), 2) + Math.pow(Math.cos(123), 2" ascii
    $s5  = "function JRuejarxvVKYsCvfz(AaRMW){ssVfKmGpjCA= '';uhzjWfecHGT=Math.round((Math.pow(Math.sin(123), 2) + Math.pow(Math.cos(123), 2" ascii
    $s6  = "function cLJwipz(KdUdBGCDiaqCOoGJDZjHWaGBWPMWgvIRnOik) {return !jegnOkTqdiq(RwPDWJnRVtXtnVi(KdUdBGCDiaqCOoGJDZjHWaGBWPMWgvIRnOik" ascii
    $s7  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s8  = "function TIHeZmhtTZFSGQTIrRHzJiaduiLOJzlqAojZpvaGkyvkfyWXJMBZXf(TUVWBSkVEIucT,UlSXSqXsPzTEgx){ return TVOHwkH[UKYKRQCj[NtvyZ(TUV" ascii
    $s9  = "function jegnOkTqdiq(EHXKhiVYkniyFM) {return isNaN(EHXKhiVYkniyFM);}" fullword ascii
    $s10 = "function J(eHgcFrYTIkQKhU,IVgibXTogLReE,bYiHVIzOAwS) {eHgcFrYTIkQKhU[IVgibXTogLReE]=bYiHVIzOAwS;}" fullword ascii
    $s11 = "function RwPDWJnRVtXtnVi(DNYgfMFrIKpEfxQkzTU) {return parseFloat(DNYgfMFrIKpEfxQkzTU);}" fullword ascii
    $s12 = "function k(nxzXmJJirzEl,ftTeNLlwJktsZN){nxzXmJJirzEl.push(ftTeNLlwJktsZN);}" fullword ascii
    $s13 = "f);return vsEFh;}" fullword ascii
    $s14 = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s15 = "function cLJwipz(KdUdBGCDiaqCOoGJDZjHWaGBWPMWgvIRnOik) {return !jegnOkTqdiq(RwPDWJnRVtXtnVi(KdUdBGCDiaqCOoGJDZjHWaGBWPMWgvIRnOik" ascii
    $s16 = "function sVfNMOkqXiXE(FtokWnaFjUkOV) {return isFinite(FtokWnaFjUkOV);}" fullword ascii
    $s17 = "function ZPwIwPRmPBQRskU(PEEofBnPWQhfVZxYp,VWSftBmPmJHOfQVkcqkVDRsyybGXPPYmVi,vcwZYTyxslSQnhYJeJyTgOqPGgDZeULVBjZ){eval(PEEofBnP" ascii
    $s18 = "function ZPwIwPRmPBQRskU(PEEofBnPWQhfVZxYp,VWSftBmPmJHOfQVkcqkVDRsyybGXPPYmVi,vcwZYTyxslSQnhYJeJyTgOqPGgDZeULVBjZ){eval(PEEofBnP" ascii
    $s19 = "function TIHeZmhtTZFSGQTIrRHzJiaduiLOJzlqAojZpvaGkyvkfyWXJMBZXf(TUVWBSkVEIucT,UlSXSqXsPzTEgx){ return TVOHwkH[UKYKRQCj[NtvyZ(TUV" ascii
    $s20 = "function NtvyZ(UHYpKrwQTiH,QBNJFjunkhcyr,zLRTFVmf){PTcV=HTMKjtjcAxiPgblGv(UHYpKrwQTiH,QBNJFjunkhcyr);vsEFh=PTcV.toString(zLRTFVm" ascii

  condition:
    uint16(0) == 0x4b55 and
    8 of them
}