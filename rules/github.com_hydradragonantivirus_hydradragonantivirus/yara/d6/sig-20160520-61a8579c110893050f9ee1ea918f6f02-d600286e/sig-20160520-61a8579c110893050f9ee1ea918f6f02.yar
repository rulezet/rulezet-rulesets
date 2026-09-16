rule sig_20160520_61a8579c110893050f9ee1ea918f6f02 {
  meta:
    description = "datamaliciousorder - file 20160520_61a8579c110893050f9ee1ea918f6f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45e064d53791a000248f1b6663005236e6f0a79b279ea8890ee5b8cba78c7af6"

  strings:
    $s1  = "function geCUNHiw(toXOk) {var STBXJtPQ=SiJdIAoNjf[2];for(var HwhDd=0;HwhDd<toXOk;HwhDd++){BKtOF+=STBXJtPQ.charAt(Math.floor(Math" ascii
    $s2  = "function geCUNHiw(toXOk) {var STBXJtPQ=SiJdIAoNjf[2];for(var HwhDd=0;HwhDd<toXOk;HwhDd++){BKtOF+=STBXJtPQ.charAt(Math.floor(Math" ascii
    $s3  = "function DgiO(nTmzNg,FAvrtbc){zfPa = SiJdIAoNjf[11].split(SiJdIAoNjf[12]);FAvrtbc.open(zfPa[0]+zfPa[2]+zfPa[3], nTmzNg, false);F" ascii
    $s4  = "function DgiO(nTmzNg,FAvrtbc){zfPa = SiJdIAoNjf[11].split(SiJdIAoNjf[12]);FAvrtbc.open(zfPa[0]+zfPa[2]+zfPa[3], nTmzNg, false);F" ascii
    $s5  = "function oFZiYXJdm(ncRImwWsf,KsTDiDs,TIAtLEJa){" fullword ascii
    $s6  = ".random()*STBXJtPQ.length));}return BKtOF;}" fullword ascii
    $s7  = "function zfesa(bFnzcnZk,ZcfQlw,NDCszjrrv){RuEPd=bFnzcnZk.split(NDCszjrrv);xsxnkan = SiJdIAoNjf[13];for(TwphsiLM=0;TwphsiLM<ZcfQl" ascii
    $s8  = "try{oFZiYXJdm(MJaaO[GFxE], NBqJFvY() + SiJdIAoNjf[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function pyLGZ(SvuexMXw,mpYsJ,jKKNYRRVNG){SvuexMXw.open();SvuexMXw.type = 1;SvuexMXw.write(mpYsJ);SvuexMXw.position = 0;SvuexMXw" ascii
    $s10 = "function zfesa(bFnzcnZk,ZcfQlw,NDCszjrrv){RuEPd=bFnzcnZk.split(NDCszjrrv);xsxnkan = SiJdIAoNjf[13];for(TwphsiLM=0;TwphsiLM<ZcfQl" ascii
    $s11 = "function iixAL(kTUadl){return new ActiveXObject(kTUadl);}" fullword ascii
    $s12 = "function pyLGZ(SvuexMXw,mpYsJ,jKKNYRRVNG){SvuexMXw.open();SvuexMXw.type = 1;SvuexMXw.write(mpYsJ);SvuexMXw.position = 0;SvuexMXw" ascii
    $s13 = "w.length;TwphsiLM++) {xsxnkan+=RuEPd[ZcfQlw[TwphsiLM]];}return xsxnkan.substring(3,xsxnkan.length);}" fullword ascii
    $s14 = "function RnGvXi(kTUadl){return kTUadl.ExpandEnvironmentStrings(SiJdIAoNjf[10])}" fullword ascii
    $s15 = "function NBqJFvY() {var tPvr=100000;var swMnEf = 100;return Math.random()*(tPvr-swMnEf)+swMnEf;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}