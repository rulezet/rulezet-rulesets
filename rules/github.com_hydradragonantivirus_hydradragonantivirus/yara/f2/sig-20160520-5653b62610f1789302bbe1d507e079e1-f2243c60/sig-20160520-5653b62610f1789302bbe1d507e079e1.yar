rule sig_20160520_5653b62610f1789302bbe1d507e079e1 {
  meta:
    description = "datamaliciousorder - file 20160520_5653b62610f1789302bbe1d507e079e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c1c1e88b560e3ec28b774a7640b9cfcaada1d59f0172b5ba55f1f87c18d0c9"

  strings:
    $s1  = "function llxSkUPI(nSgng) {var yWLZDjJF=LNvDXQVRXQJnvLsKvHEGr[2];for(var Aqjig=0;Aqjig<nSgng;Aqjig++){rTtOK+=yWLZDjJF.charAt(Math" ascii
    $s2  = "GbnuK<LoGuho.length;VRnGbnuK++) {XLywidF+=IlWZW[LoGuho[VRnGbnuK]];}return XLywidF.substring(3,XLywidF.length);}" fullword ascii
    $s3  = "function llxSkUPI(nSgng) {var yWLZDjJF=LNvDXQVRXQJnvLsKvHEGr[2];for(var Aqjig=0;Aqjig<nSgng;Aqjig++){rTtOK+=yWLZDjJF.charAt(Math" ascii
    $s4  = "function tNAQr(zzzjmYFA,LoGuho,BxmpNNmiq){IlWZW=zzzjmYFA.split(BxmpNNmiq);XLywidF = LNvDXQVRXQJnvLsKvHEGr[13];for(VRnGbnuK=0;VRn" ascii
    $s5  = "function tNAQr(zzzjmYFA,LoGuho,BxmpNNmiq){IlWZW=zzzjmYFA.split(BxmpNNmiq);XLywidF = LNvDXQVRXQJnvLsKvHEGr[13];for(VRnGbnuK=0;VRn" ascii
    $s6  = "if (SVxyLqc==0) break;" fullword ascii
    $s7  = ".floor(Math.random()*yWLZDjJF.length));}return rTtOK;}" fullword ascii
    $s8  = "function shljgbf() {var lLeW=100000;var uMeahm = 100;return Math.random()*(lLeW-uMeahm)+uMeahm;}" fullword ascii
    $s9  = "try{SVxyLqc=ElZRqNNbD(fpnvp[nbgM], shljgbf() + LNvDXQVRXQJnvLsKvHEGr[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function IAdtG(Cwlkra){return new ActiveXObject(Cwlkra);}" fullword ascii
    $s11 = "u[3], CxqRJw, false);wegZOuG.send();}" fullword ascii
    $s12 = "function naFjXg(Cwlkra){return Cwlkra.ExpandEnvironmentStrings(LNvDXQVRXQJnvLsKvHEGr[10])}" fullword ascii
    $s13 = "function bhhSv(ehktRHQH,MfQwG,APwRpSUmyC){ehktRHQH.open();ehktRHQH.type = 1;ehktRHQH.write(MfQwG);ehktRHQH.position = 0;ehktRHQH" ascii
    $s14 = "function ElZRqNNbD(EcppbeLjt,CUhMHKj,JfxMrhaP){" fullword ascii
    $s15 = "function bhhSv(ehktRHQH,MfQwG,APwRpSUmyC){ehktRHQH.open();ehktRHQH.type = 1;ehktRHQH.write(MfQwG);ehktRHQH.position = 0;ehktRHQH" ascii
    $s16 = "function Bizb(CxqRJw,wegZOuG){wSQu = LNvDXQVRXQJnvLsKvHEGr[11].split(LNvDXQVRXQJnvLsKvHEGr[12]);wegZOuG.open(wSQu[0]+wSQu[2]+wSQ" ascii
    $s17 = "function Bizb(CxqRJw,wegZOuG){wSQu = LNvDXQVRXQJnvLsKvHEGr[11].split(LNvDXQVRXQJnvLsKvHEGr[12]);wegZOuG.open(wSQu[0]+wSQu[2]+wSQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}