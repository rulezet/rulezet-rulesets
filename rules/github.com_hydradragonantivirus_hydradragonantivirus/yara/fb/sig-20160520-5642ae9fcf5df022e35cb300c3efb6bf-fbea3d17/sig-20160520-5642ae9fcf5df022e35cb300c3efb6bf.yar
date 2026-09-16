rule sig_20160520_5642ae9fcf5df022e35cb300c3efb6bf {
  meta:
    description = "datamaliciousorder - file 20160520_5642ae9fcf5df022e35cb300c3efb6bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4feb2f6179a6eaef9e2fa6fe280211a143fa504db975d3122aeb77b1b8a305b"

  strings:
    $s1  = "function IYLNDBNj(XRHBV) {var djMbZNou=FTpNJhcNCLQDy[2];for(var OkhFk=0;OkhFk<XRHBV;OkhFk++){SOOwD+=djMbZNou.charAt(Math.floor(M" ascii
    $s2  = "function IYLNDBNj(XRHBV) {var djMbZNou=FTpNJhcNCLQDy[2];for(var OkhFk=0;OkhFk<XRHBV;OkhFk++){SOOwD+=djMbZNou.charAt(Math.floor(M" ascii
    $s3  = "function RteS(IqtDPP,WpZjjiw){pgMT = FTpNJhcNCLQDy[11].split(FTpNJhcNCLQDy[12]);WpZjjiw.open(pgMT[0]+pgMT[2]+pgMT[3], IqtDPP, fa" ascii
    $s4  = "try{NQNZCtOVa(LWWAz[gjTA], otjAkra() + FTpNJhcNCLQDy[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function HsariQ(tKOOrP){return tKOOrP.ExpandEnvironmentStrings(FTpNJhcNCLQDy[10])}" fullword ascii
    $s6  = "function MrMqb(OiGOXvRg,drVFSp,rsBfdXQgE){oZuZk=OiGOXvRg.split(rsBfdXQgE);UKpxAvm = FTpNJhcNCLQDy[13];for(zWkRDEJq=0;zWkRDEJq<dr" ascii
    $s7  = "function MrMqb(OiGOXvRg,drVFSp,rsBfdXQgE){oZuZk=OiGOXvRg.split(rsBfdXQgE);UKpxAvm = FTpNJhcNCLQDy[13];for(zWkRDEJq=0;zWkRDEJq<dr" ascii
    $s8  = "function RteS(IqtDPP,WpZjjiw){pgMT = FTpNJhcNCLQDy[11].split(FTpNJhcNCLQDy[12]);WpZjjiw.open(pgMT[0]+pgMT[2]+pgMT[3], IqtDPP, fa" ascii
    $s9  = "VFSp.length;zWkRDEJq++) {UKpxAvm+=oZuZk[drVFSp[zWkRDEJq]];}return UKpxAvm.substring(3,UKpxAvm.length);}" fullword ascii
    $s10 = "ath.random()*djMbZNou.length));}return SOOwD;}" fullword ascii
    $s11 = "function BUiCC(tKOOrP){return new ActiveXObject(tKOOrP);}" fullword ascii
    $s12 = "function UyEiC(holAZWIY,QAeIY,ADQpTKhidF){holAZWIY.open();holAZWIY.type = 1;holAZWIY.write(QAeIY);holAZWIY.position = 0;holAZWIY" ascii
    $s13 = "function otjAkra() {var IKtJ=100000;var nmGwiN = 100;return Math.random()*(IKtJ-nmGwiN)+nmGwiN;}" fullword ascii
    $s14 = "function UyEiC(holAZWIY,QAeIY,ADQpTKhidF){holAZWIY.open();holAZWIY.type = 1;holAZWIY.write(QAeIY);holAZWIY.position = 0;holAZWIY" ascii
    $s15 = "function NQNZCtOVa(mAodbIulQ,wgxlERj,pprwJqYH){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}