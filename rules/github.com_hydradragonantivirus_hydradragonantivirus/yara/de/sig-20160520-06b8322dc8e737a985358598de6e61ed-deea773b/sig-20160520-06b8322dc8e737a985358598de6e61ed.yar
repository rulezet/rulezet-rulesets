rule sig_20160520_06b8322dc8e737a985358598de6e61ed {
  meta:
    description = "datamaliciousorder - file 20160520_06b8322dc8e737a985358598de6e61ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea007ff4453988c7889e8cd29ff473f4e69a43fd1044c9422b5d92a546d8a8b"

  strings:
    $s1  = "function tyYMTvyH(twhsd) {var tWzJEpgw=mWvqAKzWmxLxphNcYb[2];for(var VmScK=0;VmScK<twhsd;VmScK++){kPMPi+=tWzJEpgw.charAt(Math.fl" ascii
    $s2  = "function tyYMTvyH(twhsd) {var tWzJEpgw=mWvqAKzWmxLxphNcYb[2];for(var VmScK=0;VmScK<twhsd;VmScK++){kPMPi+=tWzJEpgw.charAt(Math.fl" ascii
    $s3  = "function SOJd(MQNkhQ,PqOilzT){Jaqg = mWvqAKzWmxLxphNcYb[11].split(mWvqAKzWmxLxphNcYb[12]);PqOilzT.open(Jaqg[0]+Jaqg[2]+Jaqg[3], " ascii
    $s4  = "function UIEVGn(ghyVVf){return ghyVVf.ExpandEnvironmentStrings(mWvqAKzWmxLxphNcYb[10])}" fullword ascii
    $s5  = "MQNkhQ, false);PqOilzT.send();}" fullword ascii
    $s6  = "function faluw(ghyVVf){return new ActiveXObject(ghyVVf);}" fullword ascii
    $s7  = "function yzkxD(dBfdCfse,jQikIZ,aAmxSFEDi){bgLdl=dBfdCfse.split(aAmxSFEDi);SSWHyTf = mWvqAKzWmxLxphNcYb[13];for(DYiUadFC=0;DYiUad" ascii
    $s8  = "function yzkxD(dBfdCfse,jQikIZ,aAmxSFEDi){bgLdl=dBfdCfse.split(aAmxSFEDi);SSWHyTf = mWvqAKzWmxLxphNcYb[13];for(DYiUadFC=0;DYiUad" ascii
    $s9  = "try{gDTGZrT=fLOyjXRmQ(VoTCR[rRYj], LnkFXbm() + mWvqAKzWmxLxphNcYb[9], 1)}catch(e){}; " fullword ascii
    $s10 = "oor(Math.random()*tWzJEpgw.length));}return kPMPi;}" fullword ascii
    $s11 = "function SOJd(MQNkhQ,PqOilzT){Jaqg = mWvqAKzWmxLxphNcYb[11].split(mWvqAKzWmxLxphNcYb[12]);PqOilzT.open(Jaqg[0]+Jaqg[2]+Jaqg[3], " ascii
    $s12 = "function fLOyjXRmQ(JLYiEdPmx,mKdRXZf,SwArfuGl){" fullword ascii
    $s13 = "if (gDTGZrT==0) break;" fullword ascii
    $s14 = "FC<jQikIZ.length;DYiUadFC++) {SSWHyTf+=bgLdl[jQikIZ[DYiUadFC]];}return SSWHyTf.substring(3,SSWHyTf.length);}" fullword ascii
    $s15 = "function HzUEd(kCAXATND,mQWEL,RfmRWTnVDr){kCAXATND.open();kCAXATND.type = 1;kCAXATND.write(mQWEL);kCAXATND.position = 0;kCAXATND" ascii
    $s16 = "function HzUEd(kCAXATND,mQWEL,RfmRWTnVDr){kCAXATND.open();kCAXATND.type = 1;kCAXATND.write(mQWEL);kCAXATND.position = 0;kCAXATND" ascii
    $s17 = "function LnkFXbm() {var jAVZ=100000;var cAgohD = 100;return Math.random()*(jAVZ-cAgohD)+cAgohD;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}