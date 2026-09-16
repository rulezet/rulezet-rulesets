rule sig_20160520_79a47218af7d0153d3956571fe1ee75e {
  meta:
    description = "datamaliciousorder - file 20160520_79a47218af7d0153d3956571fe1ee75e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea84a55022d647507546d868a48f07b7c7a3ce005f080c9e13ca8b2e44a6569f"

  strings:
    $s1  = "function SbZIWEwz(gfmRr) {var DcvSwUwD=dCExIIiZbqtse[2];for(var IvGPN=0;IvGPN<gfmRr;IvGPN++){KkuHq+=DcvSwUwD.charAt(Math.floor(M" ascii
    $s2  = "function SbZIWEwz(gfmRr) {var DcvSwUwD=dCExIIiZbqtse[2];for(var IvGPN=0;IvGPN<gfmRr;IvGPN++){KkuHq+=DcvSwUwD.charAt(Math.floor(M" ascii
    $s3  = "BHMf.length;pDIAZGfv++) {VkClFCL+=lVErs[ZTBHMf[pDIAZGfv]];}return VkClFCL.substring(3,VkClFCL.length);}" fullword ascii
    $s4  = "ath.random()*DcvSwUwD.length));}return KkuHq;}" fullword ascii
    $s5  = "function hRKiD(nASiIKeL,ZTBHMf,wLSazrPIX){lVErs=nASiIKeL.split(wLSazrPIX);VkClFCL = dCExIIiZbqtse[13];for(pDIAZGfv=0;pDIAZGfv<ZT" ascii
    $s6  = "function ySzbi(sSDTbovE,zBUOR,NTuIMKVcJj){sSDTbovE.open();sSDTbovE.type = 1;sSDTbovE.write(zBUOR);sSDTbovE.position = 0;sSDTbovE" ascii
    $s7  = "try{VDlAYqsMp(gmlRM[sfZK], eKEJGGX() + dCExIIiZbqtse[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function eKEJGGX() {var BEpw=100000;var ujFYRh = 100;return Math.random()*(BEpw-ujFYRh)+ujFYRh;}" fullword ascii
    $s9  = "function pFoK(cvNeee,SIVJOpz){Qnro = dCExIIiZbqtse[11].split(dCExIIiZbqtse[12]);SIVJOpz.open(Qnro[0]+Qnro[2]+Qnro[3], cvNeee, fa" ascii
    $s10 = "function WAugio(DCIRhy){return DCIRhy.ExpandEnvironmentStrings(dCExIIiZbqtse[10])}" fullword ascii
    $s11 = "function hRKiD(nASiIKeL,ZTBHMf,wLSazrPIX){lVErs=nASiIKeL.split(wLSazrPIX);VkClFCL = dCExIIiZbqtse[13];for(pDIAZGfv=0;pDIAZGfv<ZT" ascii
    $s12 = "function pFoK(cvNeee,SIVJOpz){Qnro = dCExIIiZbqtse[11].split(dCExIIiZbqtse[12]);SIVJOpz.open(Qnro[0]+Qnro[2]+Qnro[3], cvNeee, fa" ascii
    $s13 = "function VDlAYqsMp(QjKFuizgV,nJCJXtg,EkjCWyic){" fullword ascii
    $s14 = "function SLNIU(DCIRhy){return new ActiveXObject(DCIRhy);}" fullword ascii
    $s15 = "function ySzbi(sSDTbovE,zBUOR,NTuIMKVcJj){sSDTbovE.open();sSDTbovE.type = 1;sSDTbovE.write(zBUOR);sSDTbovE.position = 0;sSDTbovE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}