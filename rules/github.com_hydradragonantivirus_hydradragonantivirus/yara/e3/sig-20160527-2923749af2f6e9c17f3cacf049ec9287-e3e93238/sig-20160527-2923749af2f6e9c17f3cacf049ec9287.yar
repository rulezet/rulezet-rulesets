rule sig_20160527_2923749af2f6e9c17f3cacf049ec9287 {
  meta:
    description = "datamaliciousorder - file 20160527_2923749af2f6e9c17f3cacf049ec9287.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5624552e9f408be18e15c647e89fd6d39ef5cab35d2f664ce8b145d9fda3d3b2"

  strings:
    $s1  = "function EIhCYnjQQEE() {return WScript;}function JfZQdKGPCxuhR(){return zxPSYEE.ExpandEnvironmentStrings(EcgZIfq())}" fullword ascii
    $s2  = "function nwbYrJTY(JRzUPQwnwCUXYPioBpsSx,HXRcPnQHuaLrOAHqOwMqs){return JRzUPQwnwCUXYPioBpsSx.charAt(HXRcPnQHuaLrOAHqOwMqs);}" fullword ascii
    $s3  = "function nWSNHuoQDMvDvvwEM(LIgYugR,ELhet){return LIgYugR.indexOf(ELhet);}" fullword ascii
    $s4  = "function r(weWKJfZnnMOABKtofXxmW){return String.fromCharCode(weWKJfZnnMOABKtofXxmW);}" fullword ascii
    $s5  = ".length);return VAQzgXvFuDarxaN;}" fullword ascii
    $s6  = "romCharCode(92)+AyeoOQbfFDeJgKskJv[4],true);" fullword ascii
    $s7  = "function uxKIjWdBqTdVwa(){return vPCdMuftNGpM(AyeoOQbfFDeJgKskJv[12],[0,3,6],AyeoOQbfFDeJgKskJv[13]);}" fullword ascii
    $s8  = "function pwhNpRkNW(){return vPCdMuftNGpM(AyeoOQbfFDeJgKskJv[10],[2,4,8,10],AyeoOQbfFDeJgKskJv[11]);}" fullword ascii
    $s9  = "var coPtuDkKp=function(){return new ActiveXObject(AyeoOQbfFDeJgKskJv[0]);}();" fullword ascii
    $s10 = " (nAVRHij == 64) VAQzgXvFuDarxaN += r(xzXtDtvgBqNz);else if (OMrplNDeGvz == 64) VAQzgXvFuDarxaN += OhxShpMdzngklHu(xzXtDtvgBqNz," ascii
    $s11 = "function OhxShpMdzngklHu(uxTQqulIT,OIiSPvxCYMSICv){return String.fromCharCode(uxTQqulIT,OIiSPvxCYMSICv);}" fullword ascii
    $s12 = "function aNOqyqCYwTwrCYso(xwmEQvacecc,gphnazZCf,PmpEtShFHjpwrQagp){return String.fromCharCode(xwmEQvacecc,gphnazZCf,PmpEtShFHjpw" ascii
    $s13 = "var wXHfrxHzIK = coPtuDkKp.createtextfile(zxPSYEE.ExpandEnvironmentStrings(AyeoOQbfFDeJgKskJv[2]+AyeoOQbfFDeJgKskJv[3])+String.f" ascii
    $s14 = "function EcgZIfq(){return vPCdMuftNGpM(AyeoOQbfFDeJgKskJv[8],[1,5,7],AyeoOQbfFDeJgKskJv[9]);}" fullword ascii
    $s15 = "function aNOqyqCYwTwrCYso(xwmEQvacecc,gphnazZCf,PmpEtShFHjpwrQagp){return String.fromCharCode(xwmEQvacecc,gphnazZCf,PmpEtShFHjpw" ascii
    $s16 = " EpsGFb);else VAQzgXvFuDarxaN += aNOqyqCYwTwrCYso(xzXtDtvgBqNz, EpsGFb, MXiZcmVQKOwCHDId);} while (zYJGAIiYBiKgv < sFJSLlokXNjWv" ascii
    $s17 = "function vPCdMuftNGpM(QWfyCnMPFBPVQw,dcPpKH,wdHbImk){IMnCEIT=QWfyCnMPFBPVQw.split(wdHbImk);yoCEE = AyeoOQbfFDeJgKskJv[14];for(Qs" ascii
    $s18 = "DAYhofnwgf=0;QsDAYhofnwgf<dcPpKH.length;QsDAYhofnwgf++) {yoCEE+=IMnCEIT[dcPpKH[QsDAYhofnwgf]];}return yoCEE.substring(3,yoCEE.le" ascii
    $s19 = "var zxPSYEE=function(){return EIhCYnjQQEE().CreateObject(AyeoOQbfFDeJgKskJv[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function eFHRUgeAhPgQ(sFJSLlokXNjWv) {var UjiKKPGwlnpAvmxybDxJCN = WrmuAbTKrs.join(AyeoOQbfFDeJgKskJv[6]);var xzXtDtvgBqNz, EpsG" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}