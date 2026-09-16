rule sig_20160527_471b8da30899382c57a3a659181ab1ba {
  meta:
    description = "datamaliciousorder - file 20160527_471b8da30899382c57a3a659181ab1ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e533868792698827ea8a3d9ce7fc7f44387b57d4de0db3dd1dce1965e5bee1c"

  strings:
    $s1  = "function ygSpIeuI() {return WScript;}function hGjWAPaxhR(){return dvyuu.ExpandEnvironmentStrings(xYpkpdCQXMDxO())}" fullword ascii
    $s2  = "function TvjHSGQtIhjsmRnvq(AaLYKxJgHQitNhnkC,VqUZjlCkkJhDnhXkLT){return AaLYKxJgHQitNhnkC.charAt(VqUZjlCkkJhDnhXkLT);}" fullword ascii
    $s3  = "ring.fromCharCode(92)+wdLmGlcYbydVnTXcLfcKaah[4],true);" fullword ascii
    $s4  = "GrhfTFqMqWVYvt == 64) oyMGyBCUemWexvguNt += RX(jUlWEqPozaWBzgBAoVx);else if (bEOByJOsnBMRIHkzgpSZcF == 64) oyMGyBCUemWexvguNt +=" ascii
    $s5  = "var soRsOvm = xlJeqwmWkh.createtextfile(dvyuu.ExpandEnvironmentStrings(wdLmGlcYbydVnTXcLfcKaah[2]+wdLmGlcYbydVnTXcLfcKaah[3])+St" ascii
    $s6  = "function CSWAcvdFishaDBgUcuKBsJQ(uDAGIDOBh,QBAmUZlBM){return String.fromCharCode(uDAGIDOBh,QBAmUZlBM);}" fullword ascii
    $s7  = "function xYpkpdCQXMDxO(){return hxmSqB(wdLmGlcYbydVnTXcLfcKaah[8],[1,5,7],wdLmGlcYbydVnTXcLfcKaah[9]);}" fullword ascii
    $s8  = "function bNPJDOQHW(OoFNu,sJIEtiKvfdC) {var kAmbPFS=[wdLmGlcYbydVnTXcLfcKaah[15]];OoFNu[kAmbPFS[0]](sJIEtiKvfdC,0x1,0x0)}" fullword ascii
    $s9  = " CSWAcvdFishaDBgUcuKBsJQ(jUlWEqPozaWBzgBAoVx, PbZRU);else oyMGyBCUemWexvguNt += kuPAlgOaeMYBUYj(jUlWEqPozaWBzgBAoVx, PbZRU, hckV" ascii
    $s10 = "QiNXDnrBSHdNW);} while (IoDmxlkW < zWcEackMjVZhW.length);return oyMGyBCUemWexvguNt;}" fullword ascii
    $s11 = "function kuPAlgOaeMYBUYj(hgzAGuorTAOkDxjEOrDMB,MZnvvEOKjDWomDXxj,CyJpdulsRtjSyGuYqtuA){return String.fromCharCode(hgzAGuorTAOkDx" ascii
    $s12 = "function egSIlnEEj(zWcEackMjVZhW) {var mYoOHcTR = edkrVWzuFlvgBIIekTYkjE.join(wdLmGlcYbydVnTXcLfcKaah[6]);var jUlWEqPozaWBzgBAoV" ascii
    $s13 = "function hxmSqB(uIJcnrbzp,GAXAdev,LJWMqJP){pXSSv=uIJcnrbzp.split(LJWMqJP);BGUGLdFJvwpzI = wdLmGlcYbydVnTXcLfcKaah[14];for(NxOMDb" ascii
    $s14 = "var xlJeqwmWkh=function(){return new ActiveXObject(wdLmGlcYbydVnTXcLfcKaah[0]);}();" fullword ascii
    $s15 = "var dvyuu=function(){return ygSpIeuI().CreateObject(wdLmGlcYbydVnTXcLfcKaah[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s16 = "function kuPAlgOaeMYBUYj(hgzAGuorTAOkDxjEOrDMB,MZnvvEOKjDWomDXxj,CyJpdulsRtjSyGuYqtuA){return String.fromCharCode(hgzAGuorTAOkDx" ascii
    $s17 = "function egSIlnEEj(zWcEackMjVZhW) {var mYoOHcTR = edkrVWzuFlvgBIIekTYkjE.join(wdLmGlcYbydVnTXcLfcKaah[6]);var jUlWEqPozaWBzgBAoV" ascii
    $s18 = "function FBjrAessbgcTzQ(){return hxmSqB(wdLmGlcYbydVnTXcLfcKaah[12],[0,3,6],wdLmGlcYbydVnTXcLfcKaah[13]);}" fullword ascii
    $s19 = "function hxmSqB(uIJcnrbzp,GAXAdev,LJWMqJP){pXSSv=uIJcnrbzp.split(LJWMqJP);BGUGLdFJvwpzI = wdLmGlcYbydVnTXcLfcKaah[14];for(NxOMDb" ascii
    $s20 = "function lHJqeiKvzLGym(){return hxmSqB(wdLmGlcYbydVnTXcLfcKaah[10],[2,4,8,10],wdLmGlcYbydVnTXcLfcKaah[11]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}