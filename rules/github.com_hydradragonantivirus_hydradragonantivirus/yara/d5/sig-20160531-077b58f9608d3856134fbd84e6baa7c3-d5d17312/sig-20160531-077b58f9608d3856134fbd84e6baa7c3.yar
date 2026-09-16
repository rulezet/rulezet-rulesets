rule sig_20160531_077b58f9608d3856134fbd84e6baa7c3 {
  meta:
    description = "datamaliciousorder - file 20160531_077b58f9608d3856134fbd84e6baa7c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb352bd18d9811288905f57026d22c3c5c15f8cf1655d2e495776cfa0a73a1a4"

  strings:
    $s1  = "var fFnZFZZnxBcxNs=function(){return WScript.CreateObject(oCWkZ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function iZGliUyCHrAlQxd(oAxgymcMb,kCnfPcCUxJyXFjpR){return oAxgymcMb.charAt(kCnfPcCUxJyXFjpR);}" fullword ascii
    $s3  = "function rGguBdrMiykV(){return VNHdJlmLD(oCWkZ[11],[2,4,8,10],oCWkZ[12]);}" fullword ascii
    $s4  = "g,true);YerJW.WriteLine(MCwCLPTiwPnTK);YerJW.Close();}" fullword ascii
    $s5  = "var HSGmLvfkBLzRw=function(){return new ActiveXObject(oCWkZ[1]);}();" fullword ascii
    $s6  = "GnHaUjxrZmfJ += SIbSoLh(xHDfuXCFNENoixOBYdUSCz, WkZiqIhsXTCSKV);else MSdvnyuOuAGGnHaUjxrZmfJ += nNnIUqRM(xHDfuXCFNENoixOBYdUSCz," ascii
    $s7  = "function nNnIUqRM(xkaiFxjvNKLvdzMbyyOEGV,AZtWHJbEySypKnNEWrHbQsmi,tEhuf){return String.fromCharCode(xkaiFxjvNKLvdzMbyyOEGV,AZtWH" ascii
    $s8  = "function orGtCjYjH(iNMUbBnlTs,EYzxktLzBkgXYA) {var FgixQ=[oCWkZ[15]];iNMUbBnlTs[FgixQ[0]]" fullword ascii
    $s9  = " WkZiqIhsXTCSKV, VkRYBeYkwaEJ);} while (BKbbPSMktpvVLPAzpR < GIgGJagcRIwzx.length);return MSdvnyuOuAGGnHaUjxrZmfJ;}" fullword ascii
    $s10 = "function SIbSoLh(HCIDNjzlZGdd,JrGrvTtXXPwAgVuR){return String.fromCharCode(HCIDNjzlZGdd,JrGrvTtXXPwAgVuR);}" fullword ascii
    $s11 = "0xff;if (zlsPdfNqSrKEvYpcDBdB == 64) MSdvnyuOuAGGnHaUjxrZmfJ += f(xHDfuXCFNENoixOBYdUSCz);else if (YdapQWMapH == 64) MSdvnyuOuAG" ascii
    $s12 = "function SoJSVJocm(){return fFnZFZZnxBcxNs.ExpandEnvironmentStrings(vLnpM())}" fullword ascii
    $s13 = "function EQcqbFTsEhFx(){return VNHdJlmLD(oCWkZ[13],[0,3,6],oCWkZ[14]);}" fullword ascii
    $s14 = "(EYzxktLzBkgXYA,0x1,0x0)}function nvLnSOsBLmUhD(FbVxppvOMM,GnNjIbxXg,MCwCLPTiwPnTK){var YerJW=FbVxppvOMM.createtextfile(GnNjIbxX" ascii
    $s15 = "function nNnIUqRM(xkaiFxjvNKLvdzMbyyOEGV,AZtWHJbEySypKnNEWrHbQsmi,tEhuf){return String.fromCharCode(xkaiFxjvNKLvdzMbyyOEGV,AZtWH" ascii
    $s16 = "function f(vWPQrmbtGwZoSlRUlE){return String.fromCharCode(vWPQrmbtGwZoSlRUlE);}" fullword ascii
    $s17 = "(EYzxktLzBkgXYA,0x1,0x0)}function nvLnSOsBLmUhD(FbVxppvOMM,GnNjIbxXg,MCwCLPTiwPnTK){var YerJW=FbVxppvOMM.createtextfile(GnNjIbxX" ascii
    $s18 = "function vLnpM(){return VNHdJlmLD(oCWkZ[9],[1,5,7],oCWkZ[10]);}" fullword ascii
    $s19 = "function xEvqlUaEvghKf(GIgGJagcRIwzx) {var MJgGItXugwONFzrlaovlqVK = IhFIYEGveBrjWjACwZlYkZJ.join(oCWkZ[7]);var xHDfuXCFNENoixOB" ascii
    $s20 = "function VNHdJlmLD(sdFsY,ynYNSWisrKUR,cOdTZKzxzpyoF){ncawOaQXNfKuS=sdFsY.split(cOdTZKzxzpyoF);RWdNV = oCWkZ[0];for(KGALUSFd=0;KG" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}