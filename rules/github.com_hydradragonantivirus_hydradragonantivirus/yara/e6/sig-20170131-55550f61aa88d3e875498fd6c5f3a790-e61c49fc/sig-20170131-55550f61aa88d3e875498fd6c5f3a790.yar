rule sig_20170131_55550f61aa88d3e875498fd6c5f3a790 {
  meta:
    description = "datamaliciousorder - file 20170131_55550f61aa88d3e875498fd6c5f3a790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3356b4d06ce345fca7dc8a185f7ecad3065e3489268c2a5c6d586544da39b2a3"

  strings:
    $s1  = "//var xCCdzla = new Date();while(true) {var QOVrJ = new Date();var FLPSwc = new Date(QOVrJ.getTime() - xCCdzla.getTime());if(FLP" ascii
    $s2  = "Swc.getSeconds() > 7) {break;}WScript.Sleep(300);}" fullword ascii
    $s3  = "//var xCCdzla = new Date();while(true) {var QOVrJ = new Date();var FLPSwc = new Date(QOVrJ.getTime() - xCCdzla.getTime());if(FLP" ascii
    $s4  = "function iMPVHNlNqQGwnnZGrQ(hCFlspxVmFX){return hCFlspxVmFX.ExpandEnvironmentStrings('%T'+'MP%');}var KVqqM='vHaBJOLXkSlGyZaDlQT" ascii
    $s5  = "WfG,vnfGe(dJWfG)+'DolXR'+'XWIz.js');function CsadGRZ(xhXHAEGYp,lXzVijl){xhXHAEGYp.run(lXzVijl,0x0+1, 0x0);}function vnfGe(ygFI){" ascii
    $s6  = "ing.FileSystemObject');LJwol=rECMa.OpenTextFile(tspqoHveHBqtNyfg(dJWfG), 2, true);LJwol.Write(uOqsgZnv);LJwol.Close();CsadGRZ(dJ" ascii
    $s7  = "var Gix = \"PIpE[z}]ty5'a" fullword ascii
    $s8  = "function kTgNm(WXNMj){var RhfSVf = '2'+'8';var OGNATW='\"' + new Date() + '\"';var XWCohM=0;while(XWCohM<WXNMj.length){var LUawO" ascii
    $s9  = "function kTgNm(WXNMj){var RhfSVf = '2'+'8';var OGNATW='\"' + new Date() + '\"';var XWCohM=0;while(XWCohM<WXNMj.length){var LUawO" ascii
    $s10 = "fvRt.substring(0,tLhHmBEY);var SLuc = flfvRt.substring(tLhHmBEY);return vMrvJB+yZHLHvemrZ+SLuc;}" fullword ascii
    $s11 = "function MBoXM(wEPeluo){var unvtump = String.fromCharCode(wEPeluo);return unvtump;}" fullword ascii
    $s12 = "function iMPVHNlNqQGwnnZGrQ(hCFlspxVmFX){return hCFlspxVmFX.ExpandEnvironmentStrings('%T'+'MP%');}var KVqqM='vHaBJOLXkSlGyZaDlQT" ascii
    $s13 = " return ygFI.ExpandEnvironmentStrings('%'+'T'+'M'+'P'+'%')+String.fromCharCode(92);}" fullword ascii
    $s14 = "=MBoXM(RhfSVf^PhWjEwIc(WXNMj,XWCohM));OGNATW+=LUawOKL;XWCohM++;}return OGNATW;}" fullword ascii
    $s15 = "function lZyDuocnaTYxu() {return \"\"};" fullword ascii
    $s16 = "function PhWjEwIc(Mxeqv,lCRFfDWM){return Mxeqv.charCodeAt(lCRFfDWM)}function aObWPoo(flfvRt,yZHLHvemrZ,tLhHmBEY){var vMrvJB = fl" ascii
    $s17 = "function PhWjEwIc(Mxeqv,lCRFfDWM){return Mxeqv.charCodeAt(lCRFfDWM)}function aObWPoo(flfvRt,yZHLHvemrZ,tLhHmBEY){var vMrvJB = fl" ascii
    $s18 = "function tspqoHveHBqtNyfg(COfikgwmI){return iMPVHNlNqQGwnnZGrQ(COfikgwmI)+'\\\\'+'DolXR'+'XWIz.js'}" fullword ascii

  condition:
    uint16(0) == 0x2f2f and
    8 of them
}