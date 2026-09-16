rule sig_20160527_507323144d919698e50b50926434434d {
  meta:
    description = "datamaliciousorder - file 20160527_507323144d919698e50b50926434434d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "320467030a5f92c8ecaebff7cb89133eebe6b4833528dbba8c86d86ff6aa15d5"

  strings:
    $s1  = "function LGCGYGoRDW() {return WScript;}function ZQbRAFrA(){return HMIlKq.ExpandEnvironmentStrings(ryiryYOyKg())}" fullword ascii
    $s2  = "function YtsJqtDWJhexYqHwWCef(HocHGLjOMbX,TsrCYpoJHHoWHChaPzPH){return HocHGLjOMbX.charAt(TsrCYpoJHHoWHChaPzPH);}" fullword ascii
    $s3  = "function TWITpz(ZqZbYURIIPJRNFiBgHi,zPeZbHKhVKRUQJ){return String.fromCharCode(ZqZbYURIIPJRNFiBgHi,zPeZbHKhVKRUQJ);}" fullword ascii
    $s4  = "var HMIlKq=function(){return LGCGYGoRDW().CreateObject(iuZFABBY[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s5  = "function mQstcTFRT(pfcRZNuFGTeWX) {var kUdGGtXRJwVXuUa = WaroptfhxKd.join(iuZFABBY[6]);var FYHWOPmYxuexum, poLEa, rLpYQpaz, hpud" ascii
    $s6  = "var aIUwonlN = SavmKnIpOpfUG.createtextfile(HMIlKq.ExpandEnvironmentStrings(iuZFABBY[2]+iuZFABBY[3])+String.fromCharCode(92)+iuZ" ascii
    $s7  = "uexum, poLEa);else VZRqJuTficOVyHe += zCCJbnLHr(FYHWOPmYxuexum, poLEa, rLpYQpaz);} while (zcswNTEtlnA < pfcRZNuFGTeWX.length);re" ascii
    $s8  = "function ryiryYOyKg(){return GWbgpDqpw(iuZFABBY[8],[1,5,7],iuZFABBY[9]);}" fullword ascii
    $s9  = "function GWbgpDqpw(SVbjoEz,IblzBgEC,xyfaHbITK){efslaKaLy=SVbjoEz.split(xyfaHbITK);TUtxMQU = iuZFABBY[14];for(jAOeXhrEPfNRKv=0;jA" ascii
    $s10 = "function eZ(gBMRqJVFQVrExkxR){return String.fromCharCode(gBMRqJVFQVrExkxR);}" fullword ascii
    $s11 = "FABBY[4],true);" fullword ascii
    $s12 = "a & 0xff;if (xKRVJOexeJ == 64) VZRqJuTficOVyHe += eZ(FYHWOPmYxuexum);else if (ixESubH == 64) VZRqJuTficOVyHe += TWITpz(FYHWOPmYx" ascii
    $s13 = "function mjjGLcsCnKoPp(){return GWbgpDqpw(iuZFABBY[10],[2,4,8,10],iuZFABBY[11]);}" fullword ascii
    $s14 = "function ktWYKZCuDJbXvKbnp(DvevkydlwABNTf,DRzNDqvxBVVCoCrRomACPA){return DvevkydlwABNTf.indexOf(DRzNDqvxBVVCoCrRomACPA);}" fullword ascii
    $s15 = "OeXhrEPfNRKv<IblzBgEC.length;jAOeXhrEPfNRKv++) {TUtxMQU+=efslaKaLy[IblzBgEC[jAOeXhrEPfNRKv]];}return TUtxMQU.substring(3,TUtxMQU" ascii
    $s16 = "function dKqBVBsP(){return GWbgpDqpw(iuZFABBY[12],[0,3,6],iuZFABBY[13]);}" fullword ascii
    $s17 = "function aYGZREfyEuTf(PaLNFenJmI,fDiUqaM) {var dBbNGUHlHD=[iuZFABBY[15]];PaLNFenJmI[dBbNGUHlHD[0]](fDiUqaM,0x1,0x0)}" fullword ascii
    $s18 = "turn VZRqJuTficOVyHe;}" fullword ascii
    $s19 = "function mQstcTFRT(pfcRZNuFGTeWX) {var kUdGGtXRJwVXuUa = WaroptfhxKd.join(iuZFABBY[6]);var FYHWOPmYxuexum, poLEa, rLpYQpaz, hpud" ascii
    $s20 = "var SavmKnIpOpfUG=function(){return new ActiveXObject(iuZFABBY[0]);}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}