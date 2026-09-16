rule sig_20160531_0cf9580be0bd9588f8946768a2a94577 {
  meta:
    description = "datamaliciousorder - file 20160531_0cf9580be0bd9588f8946768a2a94577.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ace24f437fde5ee2fcdae4b9ae28c0d5608bd4d7207e02811b6e32b8e921913a"

  strings:
    $s1  = "var KrkNOQgjzOpHSs=function(){return WScript.CreateObject(EAeHxBkiv[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function NRYtIRYzpAvkBc(vwTJvKpyMFDFEXl,gQfyIimYzHmMVxIsC){return vwTJvKpyMFDFEXl.charAt(gQfyIimYzHmMVxIsC);}" fullword ascii
    $s3  = "push(\"t\");BwIdlKjPgQXwZZ.push(\"u\");BwIdlKjPgQXwZZ.push(\"v\");BwIdlKjPgQXwZZ.push(\"w\");BwIdlKjPgQXwZZ.push(\"x\");BwIdlKjP" ascii
    $s4  = "function znYyEdFhuhLjD(yyyjaKFUcQnVQb,ADJCu,PoNGkWONiV){return String.fromCharCode(yyyjaKFUcQnVQb,ADJCu,PoNGkWONiV);}" fullword ascii
    $s5  = "function sMxbRgFUKrYFQO(){return ZfIvABjmsGI(EAeHxBkiv[11],[2,4,8,10],EAeHxBkiv[12]);}" fullword ascii
    $s6  = "function cqCdW(){return KrkNOQgjzOpHSs.ExpandEnvironmentStrings(yRaDiq())}" fullword ascii
    $s7  = "(NCehEHuvFV,0x1,0x0)}function QdKZwfFK(yrswcrnQuzjI,tkdkKrwkCzJ,KszYbDKFJODzP){var CVPuid=yrswcrnQuzjI.createtextfile(tkdkKrwkCz" ascii
    $s8  = "function NmhbrOOn(CTfdklskhKajz) {var FldKHFbxfnvdZlSELQz = BwIdlKjPgQXwZZ.join(EAeHxBkiv[7]);var vQKqxzSVcVRyeJgQyWCRuH, JBdHeC" ascii
    $s9  = "(vPuvpxLh == 64) xJYnkDNfRmDztBqse += gR(vQKqxzSVcVRyeJgQyWCRuH);else if (DKIlRwCZLjoEuNcM == 64) xJYnkDNfRmDztBqse += ksHswbfDX" ascii
    $s10 = "function jliWDZeGgBGQvNKCl(ejYsFM,twEXSxSbLTcVbuuZbZkw){return ejYsFM.indexOf(twEXSxSbLTcVbuuZbZkw);}" fullword ascii
    $s11 = "J,true);CVPuid.WriteLine(KszYbDKFJODzP);CVPuid.Close();}" fullword ascii
    $s12 = "function gR(kmmtxjqRhUib){return String.fromCharCode(kmmtxjqRhUib);}" fullword ascii
    $s13 = "function NmhbrOOn(CTfdklskhKajz) {var FldKHFbxfnvdZlSELQz = BwIdlKjPgQXwZZ.join(EAeHxBkiv[7]);var vQKqxzSVcVRyeJgQyWCRuH, JBdHeC" ascii
    $s14 = "feaEicJhYPPrLh(vQKqxzSVcVRyeJgQyWCRuH, JBdHeC);else xJYnkDNfRmDztBqse += znYyEdFhuhLjD(vQKqxzSVcVRyeJgQyWCRuH, JBdHeC, fchlnMQ);" ascii
    $s15 = "function ksHswbfDXfeaEicJhYPPrLh(kYDQNJawnJLE,zvKXVKxswCeOZ){return String.fromCharCode(kYDQNJawnJLE,zvKXVKxswCeOZ);}" fullword ascii
    $s16 = "function yRaDiq(){return ZfIvABjmsGI(EAeHxBkiv[9],[1,5,7],EAeHxBkiv[10]);}" fullword ascii
    $s17 = "} while (sBYPjS < CTfdklskhKajz.length);return xJYnkDNfRmDztBqse;}" fullword ascii
    $s18 = "function ufVkt(yGZjUYgonK,NCehEHuvFV) {var JsFiKKzzjLCK=[EAeHxBkiv[15]];yGZjUYgonK[JsFiKKzzjLCK[0]]" fullword ascii
    $s19 = "function ZfIvABjmsGI(FsYGEmbJXSilyt,QBmtERUMtIIatp,eehKDKleUz){GqhnWWZmgccGsy=FsYGEmbJXSilyt.split(eehKDKleUz);xtauuq = EAeHxBki" ascii
    $s20 = "turn xtauuq.substring(3,xtauuq.length);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}