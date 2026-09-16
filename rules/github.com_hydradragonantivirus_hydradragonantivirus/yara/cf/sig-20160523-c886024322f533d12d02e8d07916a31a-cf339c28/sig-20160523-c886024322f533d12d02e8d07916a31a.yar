rule sig_20160523_c886024322f533d12d02e8d07916a31a {
  meta:
    description = "datamaliciousorder - file 20160523_c886024322f533d12d02e8d07916a31a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8757db58a721e3257ddbc0ebc82ce3ac665bacbdd574e802366be35184c3690"

  strings:
    $s1  = "function RHITlHdTkz(UfxnomCJ,UFGILkUEgowk) {UfxnomCJ.Run(UFGILkUEgowk, 0x1, 0x0);}" fullword ascii
    $s2  = "function EOBAAkQPkd() {return/*BSBBZzbDZMUgQLhAQtZJcguyjSNKZghVEVsNXWPaDRrQitNBWDAHzjdTSOxxJfLknrBFipGJjCKvHScWyRPejtRzntBSXKiBc" ascii
    $s3  = "function gRlRqsPy(ipZQoAvnD) {ipZQoAvnD.type=1;}" fullword ascii
    $s4  = "function VMczkWGi(zQRtO) {var NgRuOGYd=YXWcGdtLCTrbcfMBt[13];for(var ltZXi=0;ltZXi<zQRtO;ltZXi++){kHgqg+=NgRuOGYd.charAt(Math.fl" ascii
    $s5  = "function tIZwD(VHytSuBr,FnUVj,hbGaUdHsDF){ngLT(VHytSuBr);gRlRqsPy(VHytSuBr);UagIfXA(VHytSuBr,FnUVj);efSdeKsUx(VHytSuBr);cSwJ(VHy" ascii
    $s6  = "function VMczkWGi(zQRtO) {var NgRuOGYd=YXWcGdtLCTrbcfMBt[13];for(var ltZXi=0;ltZXi<zQRtO;ltZXi++){kHgqg+=NgRuOGYd.charAt(Math.fl" ascii
    $s7  = "function tIZwD(VHytSuBr,FnUVj,hbGaUdHsDF){ngLT(VHytSuBr);gRlRqsPy(VHytSuBr);UagIfXA(VHytSuBr,FnUVj);efSdeKsUx(VHytSuBr);cSwJ(VHy" ascii
    $s8  = "function efSdeKsUx(IAyYsQ) {var qzyMNsEsJn=[];IAyYsQ.position=qzyMNsEsJn.length*(2786824-437);}" fullword ascii
    $s9  = "function xUhSfpo(){return Math.random();}" fullword ascii
    $s10 = "function BIFlg(qPGJzLQD,DhcNMz,FuIxgZCoG){xNZll=qPGJzLQD.split(FuIxgZCoG);iQbEhPf = YXWcGdtLCTrbcfMBt[12];for(sYUJGFIS=0;sYUJGFI" ascii
    $s11 = "oor(Math.random()*NgRuOGYd.length));}return kHgqg;}" fullword ascii
    $s12 = "function EOBAAkQPkd() {return/*BSBBZzbDZMUgQLhAQtZJcguyjSNKZghVEVsNXWPaDRrQitNBWDAHzjdTSOxxJfLknrBFipGJjCKvHScWyRPejtRzntBSXKiBc" ascii
    $s13 = "S<DhcNMz.length;sYUJGFIS++) {iQbEhPf+=xNZll[DhcNMz[sYUJGFIS]];}return iQbEhPf.substring(3,iQbEhPf.length);}" fullword ascii
    $s14 = "function cSwJ(spxfkXH,aVJceKP) {spxfkXH.saveToFile(aVJceKP, 2);}" fullword ascii
    $s15 = "function ZbHpu(SUepCN){return new ActiveXObject(SUepCN);}" fullword ascii
    $s16 = "function zeCV(FJKajm,sNjZSma){WVQM = YXWcGdtLCTrbcfMBt[10].split(YXWcGdtLCTrbcfMBt[11]);sNjZSma.open(WVQM[0]+WVQM[2]+WVQM[3], FJ" ascii
    $s17 = "function UagIfXA(rrxF,SBcfL) {rrxF.write(SBcfL);}" fullword ascii
    $s18 = "function BIFlg(qPGJzLQD,DhcNMz,FuIxgZCoG){xNZll=qPGJzLQD.split(FuIxgZCoG);iQbEhPf = YXWcGdtLCTrbcfMBt[12];for(sYUJGFIS=0;sYUJGFI" ascii
    $s19 = "if(Xbms>iTMKf.length) break;" fullword ascii
    $s20 = "Kajm, false);sNjZSma.send();}" fullword ascii

  condition:
    uint16(0) == 0x0927 and
    8 of them
}