rule sig_20160530_d7f336764f15f62ee63895a1ca7ea1dc {
  meta:
    description = "datamaliciousorder - file 20160530_d7f336764f15f62ee63895a1ca7ea1dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712c4a77cc11055517ab37e1017875095ddbd86bfb358e3e9728a3d4660c5e85"

  strings:
    $s1  = "function yAtPSToW(mdILHZijiKsAmbat,tlRGoICXOVYAZFiKHBFzLLVH){return mdILHZijiKsAmbat.charAt(tlRGoICXOVYAZFiKHBFzLLVH);}" fullword ascii
    $s2  = "var DdcoalNGxnyC=function(){return WScript.CreateObject(RBByCaaERVvCd[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "function vKQkl(vwdXkBHKSOiycCQgGS,CGEYnu){return String.fromCharCode(vwdXkBHKSOiycCQgGS,CGEYnu);}" fullword ascii
    $s4  = "function t(eBeYAICnuU){return String.fromCharCode(eBeYAICnuU);}" fullword ascii
    $s5  = "function FOlrLbjw(){return DdcoalNGxnyC.ExpandEnvironmentStrings(DVcyzTSirFEHMR())}" fullword ascii
    $s6  = "RwTmFSriWf=0;KXRwTmFSriWf<fLoyfEHAeuiH.length;KXRwTmFSriWf++) {uPTUNFXjtF+=DomCMZv[fLoyfEHAeuiH[KXRwTmFSriWf]];}return uPTUNFXjt" ascii
    $s7  = "gNaKhkW(CYWjlJokStriGOV, MJGKAI, OgJlAYmOLLreRoGTwvUxUkp);} while (DuPPMOpHbjDtaCclXRKpDh < dEYtmbDLkuEIt.length);return qIGpFEm" ascii
    $s8  = "function OokgNaKhkW(TuTqztQDkBbu,QaccWdLTRuDmylAQhQQ,hYLlV){return String.fromCharCode(TuTqztQDkBbu,QaccWdLTRuDmylAQhQQ,hYLlV);}" ascii
    $s9  = "function OVnWGyuqkmJFonGSuMX(jGEKRvNz,hItChTXScVDua){return jGEKRvNz.indexOf(hItChTXScVDua);}" fullword ascii
    $s10 = "= t(CYWjlJokStriGOV);else if (SJCZJsLnMxCqg == 64) qIGpFEmOWKedSrl += vKQkl(CYWjlJokStriGOV, MJGKAI);else qIGpFEmOWKedSrl += Ook" ascii
    $s11 = "function KAPeGRxghncIuY(){return FqkiVDxNGaM(RBByCaaERVvCd[13],[0,3,6],RBByCaaERVvCd[14]);}" fullword ascii
    $s12 = "function vXRBIqVUP(dEYtmbDLkuEIt) {var mbZOadcjlxIeXNEuL = HroEHywmkbv.join(RBByCaaERVvCd[7]);var CYWjlJokStriGOV, MJGKAI, OgJlA" ascii
    $s13 = "92)+RBByCaaERVvCd[5],true);" fullword ascii
    $s14 = "var sAsec = JrLsDvS.createtextfile(DdcoalNGxnyC.ExpandEnvironmentStrings(RBByCaaERVvCd[3]+RBByCaaERVvCd[4])+String.fromCharCode(" ascii
    $s15 = "function DVcyzTSirFEHMR(){return FqkiVDxNGaM(RBByCaaERVvCd[9],[1,5,7],RBByCaaERVvCd[10]);}" fullword ascii
    $s16 = "var JrLsDvS=function(){return new ActiveXObject(RBByCaaERVvCd[1]);}();" fullword ascii
    $s17 = "function FqkiVDxNGaM(JadPJOne,fLoyfEHAeuiH,qRhXKsITsCB){DomCMZv=JadPJOne.split(qRhXKsITsCB);uPTUNFXjtF = RBByCaaERVvCd[0];for(KX" ascii
    $s18 = "function vXRBIqVUP(dEYtmbDLkuEIt) {var mbZOadcjlxIeXNEuL = HroEHywmkbv.join(RBByCaaERVvCd[7]);var CYWjlJokStriGOV, MJGKAI, OgJlA" ascii
    $s19 = "function pPuxhfXpJQ(XnnPrra,xkCeMDExQ) {var vXNZBlk=[RBByCaaERVvCd[15]];XnnPrra[vXNZBlk[0]]" fullword ascii
    $s20 = "function FqkiVDxNGaM(JadPJOne,fLoyfEHAeuiH,qRhXKsITsCB){DomCMZv=JadPJOne.split(qRhXKsITsCB);uPTUNFXjtF = RBByCaaERVvCd[0];for(KX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}