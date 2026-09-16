rule sig_20160523_ed0cceb3653f7546c092c0cdda5c33de {
  meta:
    description = "datamaliciousorder - file 20160523_ed0cceb3653f7546c092c0cdda5c33de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebc8c27cab6391601afe99d811b478264f89c7a3c8574569d8d4416b9720af89"

  strings:
    $s1  = "function LGkmfrDgat(ISLycjAK,YcHrlUNdrNJn) {ISLycjAK.Run(YcHrlUNdrNJn, 0x1, 0x0);}" fullword ascii
    $s2  = "function mKhBiPZBWY() {return/*MhhZYPHNmsIsohdfYLjJVLrZeAWKxdeVTIzgwVNakFLYQVcYYEJSIEswYFKGOmuaxdFQHsgcpXaEsFxVRLTwQAtXkLYsTMdZD" ascii
    $s3  = "function HgTZgZTv(cIVBp) {var qaJeevfA=dfuijJdRy[13];for(var iAnKD=0;iAnKD<cIVBp;iAnKD++){lMpZj+=qaJeevfA.charAt(Math.floor(Math" ascii
    $s4  = "function HgTZgZTv(cIVBp) {var qaJeevfA=dfuijJdRy[13];for(var iAnKD=0;iAnKD<cIVBp;iAnKD++){lMpZj+=qaJeevfA.charAt(Math.floor(Math" ascii
    $s5  = "function DyrL(MoZWtB,kBYjUwq){dPEL = dfuijJdRy[10].split(dfuijJdRy[11]);kBYjUwq.open(dPEL[0]+dPEL[2]+dPEL[3], MoZWtB, false);kBY" ascii
    $s6  = "function cntTX(myQgoHDU,DnymrJ,aIQkwlXvH){nnnOC=myQgoHDU.split(aIQkwlXvH);eZvrzUK = dfuijJdRy[12];for(cqmnrLup=0;cqmnrLup<DnymrJ" ascii
    $s7  = "function mKhBiPZBWY() {return/*MhhZYPHNmsIsohdfYLjJVLrZeAWKxdeVTIzgwVNakFLYQVcYYEJSIEswYFKGOmuaxdFQHsgcpXaEsFxVRLTwQAtXkLYsTMdZD" ascii
    $s8  = ".random()*qaJeevfA.length));}return lMpZj;}" fullword ascii
    $s9  = "function RLPBDSc(){return Math.random();}" fullword ascii
    $s10 = "function pxWmO(iqkwTVTJ,fobNI,OmcOhTygNZ){jnUU(iqkwTVTJ);lcHqllZn(iqkwTVTJ);lBGNcdk(iqkwTVTJ,fobNI);jfkeizUiS(iqkwTVTJ);hCZH(iqk" ascii
    $s11 = "function pxWmO(iqkwTVTJ,fobNI,OmcOhTygNZ){jnUU(iqkwTVTJ);lcHqllZn(iqkwTVTJ);lBGNcdk(iqkwTVTJ,fobNI);jfkeizUiS(iqkwTVTJ);hCZH(iqk" ascii
    $s12 = "function lBGNcdk(WDqv,tXAMK) {WDqv.write(tXAMK);}" fullword ascii
    $s13 = ".length;cqmnrLup++) {eZvrzUK+=nnnOC[DnymrJ[cqmnrLup]];}return eZvrzUK.substring(3,eZvrzUK.length);}" fullword ascii
    $s14 = "function DyrL(MoZWtB,kBYjUwq){dPEL = dfuijJdRy[10].split(dfuijJdRy[11]);kBYjUwq.open(dPEL[0]+dPEL[2]+dPEL[3], MoZWtB, false);kBY" ascii
    $s15 = "function MItzFFJ() {var bKTj=100000;var nREMrd = 100;return RLPBDSc()*(bKTj-nREMrd)+nREMrd;}" fullword ascii
    $s16 = "function jfkeizUiS(LivGJk) {var GGSZgFnfwK=[];LivGJk.position=GGSZgFnfwK.length*(3084290-623);}" fullword ascii
    $s17 = "function yHgyWg(zXVjgq){return zXVjgq.ExpandEnvironmentStrings(dfuijJdRy[9])}" fullword ascii
    $s18 = "function lcHqllZn(RoUXpOrkM) {RoUXpOrkM.type=1;}" fullword ascii
    $s19 = "function aErfz(zXVjgq){return new ActiveXObject(zXVjgq);}" fullword ascii
    $s20 = "function cntTX(myQgoHDU,DnymrJ,aIQkwlXvH){nnnOC=myQgoHDU.split(aIQkwlXvH);eZvrzUK = dfuijJdRy[12];for(cqmnrLup=0;cqmnrLup<DnymrJ" ascii

  condition:
    uint16(0) == 0x1727 and
    8 of them
}