rule sig_20160531_ddcaceda43891a4d5bc65788582b839f {
  meta:
    description = "datamaliciousorder - file 20160531_ddcaceda43891a4d5bc65788582b839f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c560a87da2ea2a8bed389bce63dd14bbe447a536dba4f0eab91e7a4008832de"

  strings:
    $s1  = "var hYsQFdoMtCgq=function(){return WScript.CreateObject(JzpeD[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function EZRwI(QdLqIwjKbbOSV,aEodfSgsGPL){return QdLqIwjKbbOSV.charAt(aEodfSgsGPL);}" fullword ascii
    $s3  = "var oKuRNRwayEWXI=function(){return new ActiveXObject(JzpeD[1]);}();" fullword ascii
    $s4  = "(ckaphoaFl,0x1,0x0)}function RllqDpYnMy(CUcPNF,ZdnmAvVRGlpT,aGXxmBrLow){var sOULRBBVXxbaec=CUcPNF.createtextfile(ZdnmAvVRGlpT,tr" ascii
    $s5  = "function xDHVBdgZRmRTQbrpK(PILQcfjPgyn,vrzKHWX){return PILQcfjPgyn.indexOf(vrzKHWX);}" fullword ascii
    $s6  = "function nHvdXUgDrOmIO(){return lstnGxzRgwWmD(JzpeD[11],[2,4,8,10],JzpeD[12]);}" fullword ascii
    $s7  = "function vPPZxnxyqj(){return lstnGxzRgwWmD(JzpeD[9],[1,5,7],JzpeD[10]);}" fullword ascii
    $s8  = "function HYMAFAKrchBNMpAiHdO(oSUvtrZdscQJB,hYKXkeKLfJdNDCEjrcxp,pYHjQzdAjvcpdxHceZKLqOU){return String.fromCharCode(oSUvtrZdscQJ" ascii
    $s9  = "function gJGVwBWvPt(JXUYuSPwfKvLA) {var KvNZyWlK = JSmcFU.join(JzpeD[7]);var MOTiKFYfdeQQvJQqLkkWw, yuDEnbRfkaMMLErE, SgxVTMYCxX" ascii
    $s10 = "function gJGVwBWvPt(JXUYuSPwfKvLA) {var KvNZyWlK = JSmcFU.join(JzpeD[7]);var MOTiKFYfdeQQvJQqLkkWw, yuDEnbRfkaMMLErE, SgxVTMYCxX" ascii
    $s11 = "TiKFYfdeQQvJQqLkkWw, yuDEnbRfkaMMLErE, SgxVTMYCxXdj);} while (UsSQsDNvKRBCnfZFKbvLaKn < JXUYuSPwfKvLA.length);return UahQaaY;}" fullword ascii
    $s12 = "function SpDOjHWc(){return lstnGxzRgwWmD(JzpeD[13],[0,3,6],JzpeD[14]);}" fullword ascii
    $s13 = "else if (KwPAyfEglDbG == 64) UahQaaY += ZqAYHoVY(MOTiKFYfdeQQvJQqLkkWw, yuDEnbRfkaMMLErE);else UahQaaY += HYMAFAKrchBNMpAiHdO(MO" ascii
    $s14 = "function ZqAYHoVY(XaQcwqbTnf,eOhtyxm){return String.fromCharCode(XaQcwqbTnf,eOhtyxm);}" fullword ascii
    $s15 = "function HYMAFAKrchBNMpAiHdO(oSUvtrZdscQJB,hYKXkeKLfJdNDCEjrcxp,pYHjQzdAjvcpdxHceZKLqOU){return String.fromCharCode(oSUvtrZdscQJ" ascii
    $s16 = "function QXaweCshWMyxA(){return hYsQFdoMtCgq.ExpandEnvironmentStrings(vPPZxnxyqj())}" fullword ascii
    $s17 = "(ckaphoaFl,0x1,0x0)}function RllqDpYnMy(CUcPNF,ZdnmAvVRGlpT,aGXxmBrLow){var sOULRBBVXxbaec=CUcPNF.createtextfile(ZdnmAvVRGlpT,tr" ascii
    $s18 = "J<ZpKSZkM.length;ZLkSBJ++) {hBmGMADljF+=eazfFSmo[ZpKSZkM[ZLkSBJ]];}return hBmGMADljF.substring(3,hBmGMADljF.length);}" fullword ascii
    $s19 = "function gz(xaKRFLyje){return String.fromCharCode(xaKRFLyje);}" fullword ascii
    $s20 = "function lstnGxzRgwWmD(QOavxouGSnkb,ZpKSZkM,CIBLKS){eazfFSmo=QOavxouGSnkb.split(CIBLKS);hBmGMADljF = JzpeD[0];for(ZLkSBJ=0;ZLkSB" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}