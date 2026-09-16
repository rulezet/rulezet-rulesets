rule sig_20160523_782f8cef3b35597875d2696018ff6260 {
  meta:
    description = "datamaliciousorder - file 20160523_782f8cef3b35597875d2696018ff6260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "006422ae7e3555b8a3117a8d44c1c0cbab352617b5c73d216022520f38c5fd30"

  strings:
    $s1  = "function jqynjVnZTo() {return/*VjdiKFOTEHSEYsCJpAPcQVpZrCcMEsCZXEkJTgpxjpXMqIqjJERqzEsZMJhKeCIoqMYYVLHtuipDqVttmzpCFmHGYYLpAAOUe" ascii
    $s2  = "function sTetszwDJR(nbnquudC,IXBbLJpuBAWU) {nbnquudC.Run(IXBbLJpuBAWU, 0x1, 0x0);}" fullword ascii
    $s3  = "function JvyZADtW(fxrGe) {var PCLwQOmr=hgtzjNqmJlMGdgLJLprqrK[13];for(var ummfI=0;ummfI<fxrGe;ummfI++){JFqVl+=PCLwQOmr.charAt(Ma" ascii
    $s4  = "function JvyZADtW(fxrGe) {var PCLwQOmr=hgtzjNqmJlMGdgLJLprqrK[13];for(var ummfI=0;ummfI<fxrGe;ummfI++){JFqVl+=PCLwQOmr.charAt(Ma" ascii
    $s5  = "function vIMjg(UMqfgKzR,ulWMs,bKrWPuOCKx){PhNa(UMqfgKzR);zNFauPFE(UMqfgKzR);whgXsGA(UMqfgKzR,ulWMs);NtJhAOFME(UMqfgKzR);cYhL(UMq" ascii
    $s6  = "th.floor(Math.random()*PCLwQOmr.length));}return JFqVl;}" fullword ascii
    $s7  = "function HfUEgA(pxxqdK){return pxxqdK.ExpandEnvironmentStrings(hgtzjNqmJlMGdgLJLprqrK[9])}" fullword ascii
    $s8  = "fBZvuU<cfDyUD.length;CgfBZvuU++) {XKpAAVh+=OpRPh[cfDyUD[CgfBZvuU]];}return XKpAAVh.substring(3,XKpAAVh.length);}" fullword ascii
    $s9  = "function ncUPZuDqzIDQf() {jqynjVnZTo().Sleep(2467613-241);}" fullword ascii
    $s10 = "function mzlV(EKqdYq,vHQFlsR){waru = hgtzjNqmJlMGdgLJLprqrK[10].split(hgtzjNqmJlMGdgLJLprqrK[11]);vHQFlsR.open(waru[0]+waru[2]+w" ascii
    $s11 = "function whgXsGA(Wihi,WzOKj) {Wihi.write(WzOKj);}" fullword ascii
    $s12 = "function DOklo(pxxqdK){return new ActiveXObject(pxxqdK);}" fullword ascii
    $s13 = "function mzlV(EKqdYq,vHQFlsR){waru = hgtzjNqmJlMGdgLJLprqrK[10].split(hgtzjNqmJlMGdgLJLprqrK[11]);vHQFlsR.open(waru[0]+waru[2]+w" ascii
    $s14 = "function NtJhAOFME(vPzZRy) {var UKwfdiYAMT=[];vPzZRy.position=UKwfdiYAMT.length*(1659476-513);}" fullword ascii
    $s15 = "function PhNa(peeAAi) {peeAAi.open();}" fullword ascii
    $s16 = "function cYhL(pynpnCv,pNXFPOp) {pynpnCv.saveToFile(pNXFPOp, 2);}" fullword ascii
    $s17 = "function bKFgj(LHWxGPpS,cfDyUD,qmUpLPtDU){OpRPh=LHWxGPpS.split(qmUpLPtDU);XKpAAVh = hgtzjNqmJlMGdgLJLprqrK[12];for(CgfBZvuU=0;Cg" ascii
    $s18 = "function oGNmvQg(hkhZR) {hkhZR.close();}" fullword ascii
    $s19 = "function yLOKHsa(){return Math.random();}" fullword ascii
    $s20 = "function zNFauPFE(AzCnAVxLD) {AzCnAVxLD.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x1727 and
    8 of them
}