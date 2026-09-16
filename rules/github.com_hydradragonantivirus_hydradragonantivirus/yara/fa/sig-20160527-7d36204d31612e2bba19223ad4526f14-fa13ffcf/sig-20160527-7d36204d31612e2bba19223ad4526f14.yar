rule sig_20160527_7d36204d31612e2bba19223ad4526f14 {
  meta:
    description = "datamaliciousorder - file 20160527_7d36204d31612e2bba19223ad4526f14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f002db43919e5ff0f6f293e3e97453ce40620b29d1d39475a5df3a01f8f6bde1"

  strings:
    $s1  = "function rkEYsmi(zdDLBVglkiWuSKSXNH,DgMxzUafPdQsvgLkJJVoVBLE){return zdDLBVglkiWuSKSXNH.charAt(DgMxzUafPdQsvgLkJJVoVBLE);}" fullword ascii
    $s2  = "function pYYYJLOAZOwM() {return WScript;}function qMAmZiF(){return hNmZnztZRvgasF.ExpandEnvironmentStrings(lhqznVfxSW())}" fullword ascii
    $s3  = "function AzHACpq(){return cCyps(kUQsFZ[10],[2,4,8,10],kUQsFZ[11]);}" fullword ascii
    $s4  = "push(\"U\");vsGDWOGoYrNy.push(\"V\");vsGDWOGoYrNy.push(\"W\");vsGDWOGoYrNy.push(\"X\");vsGDWOGoYrNy.push(\"Y\");vsGDWOGoYrNy.pus" ascii
    $s5  = "function atNKzxHfHGUyadYOpC(LAWcDubuIUSSYFoPG,FIJQXY,lIKlNaxFpRV){return String.fromCharCode(LAWcDubuIUSSYFoPG,FIJQXY,lIKlNaxFpR" ascii
    $s6  = ")+kUQsFZ[4],true);" fullword ascii
    $s7  = "UPPzvMpI=0;UPPzvMpI<FEmDnlotjMoOl.length;UPPzvMpI++) {rcIRuo+=ArwqiezvLCiClZ[FEmDnlotjMoOl[UPPzvMpI]];}return rcIRuo.substring(3" ascii
    $s8  = "var hNmZnztZRvgasF=function(){return pYYYJLOAZOwM().CreateObject(kUQsFZ[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s9  = "function rlnLgl(EBuwwJxRafUtHBqWTZeYO,XurBKY){return EBuwwJxRafUtHBqWTZeYO.indexOf(XurBKY);}" fullword ascii
    $s10 = "function lREmGdxO(){return cCyps(kUQsFZ[12],[0,3,6],kUQsFZ[13]);}" fullword ascii
    $s11 = "var oFfiGDXtsxkK = ptcZBJyuPA.createtextfile(hNmZnztZRvgasF.ExpandEnvironmentStrings(kUQsFZ[2]+kUQsFZ[3])+String.fromCharCode(92" ascii
    $s12 = "kYoCoauHg(TcuhsefQ, ernTAdAMcUVCH);else toZBSmKAzygxJxxjGJ += atNKzxHfHGUyadYOpC(TcuhsefQ, ernTAdAMcUVCH, tyChnmkHNH);} while (H" ascii
    $s13 = "function atNKzxHfHGUyadYOpC(LAWcDubuIUSSYFoPG,FIJQXY,lIKlNaxFpRV){return String.fromCharCode(LAWcDubuIUSSYFoPG,FIJQXY,lIKlNaxFpR" ascii
    $s14 = "function rU(MNGmQN){return String.fromCharCode(MNGmQN);}" fullword ascii
    $s15 = "ornAidzFzpeFaVs < IibTCZBlbQHHv.length);return toZBSmKAzygxJxxjGJ;}" fullword ascii
    $s16 = "hpjsNJsqTN == 64) toZBSmKAzygxJxxjGJ += rU(TcuhsefQ);else if (sulXRISOYXMnnghQVivYYUF == 64) toZBSmKAzygxJxxjGJ += spcJUeqKdilFl" ascii
    $s17 = "function PpZoSKiOC(HTTLVZZLlTGRCQ,yZlMt) {var XlFNVylYHKe=[kUQsFZ[15]];HTTLVZZLlTGRCQ[XlFNVylYHKe[0]](yZlMt,0x1,0x0)}" fullword ascii
    $s18 = "function spcJUeqKdilFlkYoCoauHg(iFWFTfriVcwhXSWBmjyrjFs,aAlFfA){return String.fromCharCode(iFWFTfriVcwhXSWBmjyrjFs,aAlFfA);}" fullword ascii
    $s19 = "var ptcZBJyuPA=function(){return new ActiveXObject(kUQsFZ[0]);}();" fullword ascii
    $s20 = "function cCyps(BeCwXxeIJfZEe,FEmDnlotjMoOl,NiJZlICVDYT){ArwqiezvLCiClZ=BeCwXxeIJfZEe.split(NiJZlICVDYT);rcIRuo = kUQsFZ[14];for(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}