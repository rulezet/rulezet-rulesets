rule sig_20160404_ad1c31ebd9edb940d6ab994acaaa0a0b {
  meta:
    description = "datamaliciousorder - file 20160404_ad1c31ebd9edb940d6ab994acaaa0a0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65362290217b863cab9f039b1eb2bbf479570565b0cc87428acec42ae02552a4"

  strings:
    $s1  = "var nK = true  , SgpA = qYb[7] + qYb[9] + qYb[11];" fullword ascii
    $s2  = "return zzrQpJM[0] + zzrQpJM[2] + zzrQpJM[4] + \".F\" + zzrQpJM[7] + zzrQpJM[9] + zzrQpJM[12] + zzrQpJM[14];" fullword ascii
    $s3  = "var qYb = (\"2.XMLHTTP eoEPJZr IBiJP XML ream St fIMpHaMC AD bTgplWJ O tcGS D\").split(\" \");" fullword ascii
    $s4  = "var zzrQpJM = evtBW(AlZhqwoOXx+\" \"+\"System zz LejyO Obj ezEijx ect tVzlfpA ObBlf\", \" \");" fullword ascii
    $s5  = "XyPK.open(Hosal,jaYwk,false);" fullword ascii
    $s6  = "return YQA.split(OuKCs);" fullword ascii
    $s7  = "function EnBqeh(ccTw,GSJtyj) {" fullword ascii
    $s8  = "return Bgrla.status;" fullword ascii
    $s9  = "function jZMrDHr(kWUA,WrZWq) {" fullword ascii
    $s10 = "function WCxHqckn(zrL) {" fullword ascii
    $s11 = "return znCG[fonzGU[0]];" fullword ascii
    $s12 = "function jwPz(hxSVK) {" fullword ascii
    $s13 = "function SrFV(Bgrla) {" fullword ascii
    $s14 = "function TqBP(qrEhe,gKwZu) {" fullword ascii
    $s15 = "function wflva(NloEqd) {" fullword ascii
    $s16 = "return vJdpUsq;" fullword ascii
    $s17 = "return new ActiveXObject(kLbH);" fullword ascii
    $s18 = "return LGbV;" fullword ascii
    $s19 = "function xLNl(ExKNF) {" fullword ascii
    $s20 = "function vtrfC(qqhjhOAc,cBqO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}