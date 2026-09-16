rule sig_20151214_8f66122a463d21202fc60432da686335 {
  meta:
    description = "datamaliciousorder - file 20151214_8f66122a463d21202fc60432da686335.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ac786584e844b049174fc3bff693bda0bcae4a48a1497919b67e6e47be0894"

  strings:
    $s1  = "function FLtlYgloRhyVfdPTc(scqYL){qRVgwfMnCxb= Z[1735];for(XyJPZSDAhLL=Math.round((Math.pow(Math.sin(8), 2) + Math.pow(Math.cos(" ascii
    $s2  = "pow(Math.cos(348), 2) - 1)); while(true) { if(dBFxBHiWI[XyJPZSDAhLL] > scqYL[XyJPZSDAhLL].length-(-104+406)/302) { break; } if (" ascii
    $s3  = "8), 2) - 1)); XyJPZSDAhLL < (621+603)/612; XyJPZSDAhLL++) {dBFxBHiWI[XyJPZSDAhLL]=Math.round((Math.pow(Math.sin(348), 2) + Math." ascii
    $s4  = "(Math.cos(667), 2) - 1)));} dBFxBHiWI[XyJPZSDAhLL]++;}} return qRVgwfMnCxb}" fullword ascii
    $s5  = "function FLtlYgloRhyVfdPTc(scqYL){qRVgwfMnCxb= Z[1735];for(XyJPZSDAhLL=Math.round((Math.pow(Math.sin(8), 2) + Math.pow(Math.cos(" ascii
    $s6  = "fQkd)) {return (String.fromCharCode(TfWkhXikoYVafQkd) + String.fromCharCode((15782+366)/367));}}" fullword ascii
    $s7  = "function ZLrMgmC(jxjKxCPxJxVNDftbZQhYnonzkoVckfhPYGdF) {return !isNaN(parseFloat(jxjKxCPxJxVNDftbZQhYnonzkoVckfhPYGdF)) && isFin" ascii
    $s8  = "function ZLrMgmC(jxjKxCPxJxVNDftbZQhYnonzkoVckfhPYGdF) {return !isNaN(parseFloat(jxjKxCPxJxVNDftbZQhYnonzkoVckfhPYGdF)) && isFin" ascii
    $s9  = "function NCPiDbeSlFQLGqY(GZvcPwsglmmIiYObu){eval(GZvcPwsglmmIiYObu)}" fullword ascii
    $s10 = " DlEkL;}function NCPiDbeSlFQLGqY(GZvcPwsglmmIiYObu,qUqWrKOTrGnYsoMoIMbyauKaaAEWzeYWUw,OZLeCgaThXbbsAblUAHwKVbpWXbxJDbwSnL){eval(" ascii
    $s11 = "function JMBJI(tQnKZGNXFFI,vuSyRJWErMBoc,HmdAWXgG){HUib=parseInt(tQnKZGNXFFI,vuSyRJWErMBoc);DlEkL=HUib.toString(HmdAWXgG);return" ascii
    $s12 = "function IdPyOwKtrpo(oTvarCxb,eCWKZK){return oTvarCxb.split(eCWKZK)}" fullword ascii
    $s13 = "function ZARcZHmAZmZjiRKSVShQHyBzZFlLFtiqybDrGoreEigFGxxHZgbrqe(cECRtKAmCjnJN,OKrNfzmCRVZqtb){ return LxAFmve[DpToqCzC[JMBJI(cEC" ascii
    $s14 = "function ZARcZHmAZmZjiRKSVShQHyBzZFlLFtiqybDrGoreEigFGxxHZgbrqe(cECRtKAmCjnJN,OKrNfzmCRVZqtb){ return LxAFmve[DpToqCzC[JMBJI(cEC" ascii
    $s15 = "function JMBJI(tQnKZGNXFFI,vuSyRJWErMBoc,HmdAWXgG){HUib=parseInt(tQnKZGNXFFI,vuSyRJWErMBoc);DlEkL=HUib.toString(HmdAWXgG);return" ascii
    $s16 = "function m(eCJbcAJaLNCN,HzPgBXnGHRvapn){eCJbcAJaLNCN.push(HzPgBXnGHRvapn);}function L0(TfWkhXikoYVafQkd){if(ZLrMgmC(TfWkhXikoYVa" ascii
    $s17 = "var Z=new Array();" fullword ascii
    $s18 = "function m(eCJbcAJaLNCN,HzPgBXnGHRvapn){eCJbcAJaLNCN.push(HzPgBXnGHRvapn);}function L0(TfWkhXikoYVafQkd){if(ZLrMgmC(TfWkhXikoYVa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}