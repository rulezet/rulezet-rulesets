rule sig_20160520_a1cdb3c240073c2abca4f731c3a004f1 {
  meta:
    description = "datamaliciousorder - file 20160520_a1cdb3c240073c2abca4f731c3a004f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80e4a87d8be54ffef4c6315e6f8264e4d149ab03fbb02c89603f93cb9327d506"

  strings:
    $s1  = "function LOOglkrG(DmfTS) {var eWUJAigg=XMElEVE[2];for(var IGBQq=0;IGBQq<DmfTS;IGBQq++){JFQIi+=eWUJAigg.charAt(Math.floor(Math.ra" ascii
    $s2  = "function sWfj(vnRLIA,JIRcgfi){JgIr = XMElEVE[11].split(XMElEVE[12]);JIRcgfi.open(JgIr[0]+JgIr[2]+JgIr[3], vnRLIA, false);JIRcgfi" ascii
    $s3  = "function sWfj(vnRLIA,JIRcgfi){JgIr = XMElEVE[11].split(XMElEVE[12]);JIRcgfi.open(JgIr[0]+JgIr[2]+JgIr[3], vnRLIA, false);JIRcgfi" ascii
    $s4  = "function LOOglkrG(DmfTS) {var eWUJAigg=XMElEVE[2];for(var IGBQq=0;IGBQq<DmfTS;IGBQq++){JFQIi+=eWUJAigg.charAt(Math.floor(Math.ra" ascii
    $s5  = "function kLfgY(jevWiWwn,ADQKD,zGyjHzoJBy){jevWiWwn.open();jevWiWwn.type = 1;jevWiWwn.write(ADQKD);jevWiWwn.position = 0;jevWiWwn" ascii
    $s6  = "function ATIFg(lLUrWL){return new ActiveXObject(lLUrWL);}" fullword ascii
    $s7  = "function pHpji(XmCUSuJD,EEDNTj,JEVbYHwxV){FFiSz=XmCUSuJD.split(JEVbYHwxV);msfexsR = XMElEVE[13];for(bIpyqqWg=0;bIpyqqWg<EEDNTj.l" ascii
    $s8  = "function kLfgY(jevWiWwn,ADQKD,zGyjHzoJBy){jevWiWwn.open();jevWiWwn.type = 1;jevWiWwn.write(ADQKD);jevWiWwn.position = 0;jevWiWwn" ascii
    $s9  = "function dHSnViGep(tYKiTFzaN,NmOFhrX,BZFAfZvU){" fullword ascii
    $s10 = "function zSnlfUx() {var uiut=100000;var ugymdX = 100;return Math.random()*(uiut-ugymdX)+ugymdX;}" fullword ascii
    $s11 = "try{dHSnViGep(ArKeC[Vilt], zSnlfUx() + XMElEVE[9], 1)}catch(e){}; " fullword ascii
    $s12 = "ength;bIpyqqWg++) {msfexsR+=FFiSz[EEDNTj[bIpyqqWg]];}return msfexsR.substring(3,msfexsR.length);}" fullword ascii
    $s13 = "function KllBav(lLUrWL){return lLUrWL.ExpandEnvironmentStrings(XMElEVE[10])}" fullword ascii
    $s14 = "function pHpji(XmCUSuJD,EEDNTj,JEVbYHwxV){FFiSz=XmCUSuJD.split(JEVbYHwxV);msfexsR = XMElEVE[13];for(bIpyqqWg=0;bIpyqqWg<EEDNTj.l" ascii
    $s15 = "ndom()*eWUJAigg.length));}return JFQIi;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}