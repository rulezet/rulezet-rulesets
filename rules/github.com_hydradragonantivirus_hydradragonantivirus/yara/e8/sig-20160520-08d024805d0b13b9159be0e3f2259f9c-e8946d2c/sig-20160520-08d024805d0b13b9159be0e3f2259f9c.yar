rule sig_20160520_08d024805d0b13b9159be0e3f2259f9c {
  meta:
    description = "datamaliciousorder - file 20160520_08d024805d0b13b9159be0e3f2259f9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8edaa405488c0e101ca9cc6e97240ee7f6f964c20aada3aad328d67aa8949853"

  strings:
    $s1  = "function jeKTwpBc(WlcXw) {var mKIgjzPM=oXQHomUbmMFO[2];for(var uSwAM=0;uSwAM<WlcXw;uSwAM++){PjfBN+=mKIgjzPM.charAt(Math.floor(Ma" ascii
    $s2  = "function jeKTwpBc(WlcXw) {var mKIgjzPM=oXQHomUbmMFO[2];for(var uSwAM=0;uSwAM<WlcXw;uSwAM++){PjfBN+=mKIgjzPM.charAt(Math.floor(Ma" ascii
    $s3  = "umG.length;VHtLTbZx++) {jBGBVJz+=rgvfr[FVVumG[VHtLTbZx]];}return jBGBVJz.substring(3,jBGBVJz.length);}" fullword ascii
    $s4  = "function cRYjK(pxUgbfRb,qweGc,tmHCvvqIzj){pxUgbfRb.open();pxUgbfRb.type = 1;pxUgbfRb.write(qweGc);pxUgbfRb.position = 0;pxUgbfRb" ascii
    $s5  = "th.random()*mKIgjzPM.length));}return PjfBN;}" fullword ascii
    $s6  = "function rLgH(VFmuQG,rAlGsGS){YOPW = oXQHomUbmMFO[11].split(oXQHomUbmMFO[12]);rAlGsGS.open(YOPW[0]+YOPW[2]+YOPW[3], VFmuQG, fals" ascii
    $s7  = "function cRYjK(pxUgbfRb,qweGc,tmHCvvqIzj){pxUgbfRb.open();pxUgbfRb.type = 1;pxUgbfRb.write(qweGc);pxUgbfRb.position = 0;pxUgbfRb" ascii
    $s8  = "function rLgH(VFmuQG,rAlGsGS){YOPW = oXQHomUbmMFO[11].split(oXQHomUbmMFO[12]);rAlGsGS.open(YOPW[0]+YOPW[2]+YOPW[3], VFmuQG, fals" ascii
    $s9  = "function QosivOEbz(WchwZOOLV,gGPNpAG,hbPIiAqU){" fullword ascii
    $s10 = "if (aHPhkux==0) break;" fullword ascii
    $s11 = "function EXsucqb() {var infc=100000;var MQYPFR = 100;return Math.random()*(infc-MQYPFR)+MQYPFR;}" fullword ascii
    $s12 = "function HVOMv(dbXMjY){return new ActiveXObject(dbXMjY);}" fullword ascii
    $s13 = "function bmYVxY(dbXMjY){return dbXMjY.ExpandEnvironmentStrings(oXQHomUbmMFO[10])}" fullword ascii
    $s14 = "try{aHPhkux=QosivOEbz(WOMky[tytw], EXsucqb() + oXQHomUbmMFO[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function AjGyO(CaaTgrIu,FVVumG,LAMPDQpnv){rgvfr=CaaTgrIu.split(LAMPDQpnv);jBGBVJz = oXQHomUbmMFO[13];for(VHtLTbZx=0;VHtLTbZx<FVV" ascii
    $s16 = "function AjGyO(CaaTgrIu,FVVumG,LAMPDQpnv){rgvfr=CaaTgrIu.split(LAMPDQpnv);jBGBVJz = oXQHomUbmMFO[13];for(VHtLTbZx=0;VHtLTbZx<FVV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}