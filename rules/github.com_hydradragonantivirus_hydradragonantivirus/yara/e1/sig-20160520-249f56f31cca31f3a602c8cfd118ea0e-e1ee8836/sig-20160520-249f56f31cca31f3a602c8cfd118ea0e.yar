rule sig_20160520_249f56f31cca31f3a602c8cfd118ea0e {
  meta:
    description = "datamaliciousorder - file 20160520_249f56f31cca31f3a602c8cfd118ea0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8426f63323a91f5a0c69251e3c92d932b719a34b2a9e61fc9e2347bd7720962"

  strings:
    $s1  = "function URywdLPT(tSSau) {var YZpmpdLz=zQxXTuFNjNARbA[2];for(var BvLnV=0;BvLnV<tSSau;BvLnV++){SoghO+=YZpmpdLz.charAt(Math.floor(" ascii
    $s2  = "function URywdLPT(tSSau) {var YZpmpdLz=zQxXTuFNjNARbA[2];for(var BvLnV=0;BvLnV<tSSau;BvLnV++){SoghO+=YZpmpdLz.charAt(Math.floor(" ascii
    $s3  = "try{xaDSAMKla(TUloY[pyvo], ehfmGMg() + zQxXTuFNjNARbA[9], 1)}catch(e){}; " fullword ascii
    $s4  = "function xaDSAMKla(WCvvKsoJG,RioQkVk,SiTVRYUs){" fullword ascii
    $s5  = "Math.random()*YZpmpdLz.length));}return SoghO;}" fullword ascii
    $s6  = "OFxol.length;xOcJUXHh++) {WFwOIjK+=fXUdk[eOFxol[xOcJUXHh]];}return WFwOIjK.substring(3,WFwOIjK.length);}" fullword ascii
    $s7  = "function ehfmGMg() {var bbeA=100000;var jlNacK = 100;return Math.random()*(bbeA-jlNacK)+jlNacK;}" fullword ascii
    $s8  = "function bLQpD(NTPYQv){return new ActiveXObject(NTPYQv);}" fullword ascii
    $s9  = "function LSFPCq(NTPYQv){return NTPYQv.ExpandEnvironmentStrings(zQxXTuFNjNARbA[10])}" fullword ascii
    $s10 = "function dSIAY(aQjLlKuZ,QPlbH,eoDdbHPWFW){aQjLlKuZ.open();aQjLlKuZ.type = 1;aQjLlKuZ.write(QPlbH);aQjLlKuZ.position = 0;aQjLlKuZ" ascii
    $s11 = "false);lKEZYEf.send();}" fullword ascii
    $s12 = "function wCnl(LOYgtZ,lKEZYEf){gJRg = zQxXTuFNjNARbA[11].split(zQxXTuFNjNARbA[12]);lKEZYEf.open(gJRg[0]+gJRg[2]+gJRg[3], LOYgtZ, " ascii
    $s13 = "function wCnl(LOYgtZ,lKEZYEf){gJRg = zQxXTuFNjNARbA[11].split(zQxXTuFNjNARbA[12]);lKEZYEf.open(gJRg[0]+gJRg[2]+gJRg[3], LOYgtZ, " ascii
    $s14 = "function Frggi(eQwRfnxm,eOFxol,UevWOlINk){fXUdk=eQwRfnxm.split(UevWOlINk);WFwOIjK = zQxXTuFNjNARbA[13];for(xOcJUXHh=0;xOcJUXHh<e" ascii
    $s15 = "function dSIAY(aQjLlKuZ,QPlbH,eoDdbHPWFW){aQjLlKuZ.open();aQjLlKuZ.type = 1;aQjLlKuZ.write(QPlbH);aQjLlKuZ.position = 0;aQjLlKuZ" ascii
    $s16 = "function Frggi(eQwRfnxm,eOFxol,UevWOlINk){fXUdk=eQwRfnxm.split(UevWOlINk);WFwOIjK = zQxXTuFNjNARbA[13];for(xOcJUXHh=0;xOcJUXHh<e" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}