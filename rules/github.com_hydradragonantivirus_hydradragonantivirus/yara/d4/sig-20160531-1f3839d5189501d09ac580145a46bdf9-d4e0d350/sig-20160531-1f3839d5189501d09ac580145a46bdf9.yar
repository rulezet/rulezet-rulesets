rule sig_20160531_1f3839d5189501d09ac580145a46bdf9 {
  meta:
    description = "datamaliciousorder - file 20160531_1f3839d5189501d09ac580145a46bdf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "551bfa061fbaac0e7b72155a4d97d0f54425ecf1bff4dbbf72505b23f43732e6"

  strings:
    $s1  = "var qxLkuyMHWN=function(){return WScript.CreateObject(rPbCElcJSLRYVHCUObJ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ixwkQYd(isFnlsRPvbKDOf,KlPykJYnQajFjBEPoIr){return isFnlsRPvbKDOf.charAt(KlPykJYnQajFjBEPoIr);}" fullword ascii
    $s3  = ";for(BUukllK=0;BUukllK<OoxAwmpHtiDki.length;BUukllK++) {wjoHqcCIYUWRiR+=UFdFHjYx[OoxAwmpHtiDki[BUukllK]];}return wjoHqcCIYUWRiR." ascii
    $s4  = "function ihFHIgWePJrpBrucboFlh(gpzMXPtxwkgg,YvCqrImfxiEKyhvaNAlqFwAH,fnVkIlrUtPnSkDYlBfFEw){return String.fromCharCode(gpzMXPtxw" ascii
    $s5  = "var tJsEY=function(){return new ActiveXObject(rPbCElcJSLRYVHCUObJ[1]);}();" fullword ascii
    $s6  = "(clxTEcwbeCgbB,0x1,0x0)}function ZGrGRLclwr(RBFIJdpfqihAu,LNewESMO,GxKKrQWGGbmR){var qOhYT=RBFIJdpfqihAu.createtextfile(LNewESMO" ascii
    $s7  = "function fpjMdlCha(){return xIUlMUFkiTMH(rPbCElcJSLRYVHCUObJ[9],[1,5,7],rPbCElcJSLRYVHCUObJ[10]);}" fullword ascii
    $s8  = "function olBTbZMdV(){return xIUlMUFkiTMH(rPbCElcJSLRYVHCUObJ[11],[2,4,8,10],rPbCElcJSLRYVHCUObJ[12]);}" fullword ascii
    $s9  = "4) NpOjoiiXc += joIboEuOPtEmIBoMcEMKjf(hIBwxdfaQolnZaOaI, iluXJglRzeoeUSEZmJTCFSp);else NpOjoiiXc += ihFHIgWePJrpBrucboFlh(hIBwx" ascii
    $s10 = "function ihFHIgWePJrpBrucboFlh(gpzMXPtxwkgg,YvCqrImfxiEKyhvaNAlqFwAH,fnVkIlrUtPnSkDYlBfFEw){return String.fromCharCode(gpzMXPtxw" ascii
    $s11 = ",true);qOhYT.WriteLine(GxKKrQWGGbmR);qOhYT.Close();}" fullword ascii
    $s12 = "S>> 8 & 0xff;iGofVpQWnz = DfIWqssVS & 0xff;if (ahadFknDVrnGpUWXQq == 64) NpOjoiiXc += js(hIBwxdfaQolnZaOaI);else if (YyHKwB == 6" ascii
    $s13 = "function joIboEuOPtEmIBoMcEMKjf(UsagNXEnwyTx,jYkWZANxmv){return String.fromCharCode(UsagNXEnwyTx,jYkWZANxmv);}" fullword ascii
    $s14 = "dfaQolnZaOaI, iluXJglRzeoeUSEZmJTCFSp, iGofVpQWnz);} while (MQOltlaTUba < VOwjYpYVhWoGY.length);return NpOjoiiXc;}" fullword ascii
    $s15 = "function mJdZYNwOCjrbhi(VOwjYpYVhWoGY) {var mnCYlxcFkblbTU = XPfyRAlToZuk.join(rPbCElcJSLRYVHCUObJ[7]);var hIBwxdfaQolnZaOaI, il" ascii
    $s16 = "function DUymflSWdu(){return qxLkuyMHWN.ExpandEnvironmentStrings(fpjMdlCha())}" fullword ascii
    $s17 = "function xIUlMUFkiTMH(MlRCGz,OoxAwmpHtiDki,AZYeHXiOZq){UFdFHjYx=MlRCGz.split(AZYeHXiOZq);wjoHqcCIYUWRiR = rPbCElcJSLRYVHCUObJ[0]" ascii
    $s18 = "push(\"U\");XPfyRAlToZuk.push(\"V\");XPfyRAlToZuk.push(\"W\");XPfyRAlToZuk.push(\"X\");XPfyRAlToZuk.push(\"Y\");XPfyRAlToZuk.pus" ascii
    $s19 = "function kAlzUGOlRj(){return xIUlMUFkiTMH(rPbCElcJSLRYVHCUObJ[13],[0,3,6],rPbCElcJSLRYVHCUObJ[14]);}" fullword ascii
    $s20 = "function js(LVfUmUeKHQdZDPcyGv){return String.fromCharCode(LVfUmUeKHQdZDPcyGv);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}