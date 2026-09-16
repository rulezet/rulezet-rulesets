rule sig_20160427_03e748ebff0c7c7093af97ba66047b0d {
  meta:
    description = "datamaliciousorder - file 20160427_03e748ebff0c7c7093af97ba66047b0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb8d01e37599e55d32649b0e2da7c5cf8460c3ec270b58cf8d9db9cf9242c574"

  strings:
    $s1  = "SbkeuZjzki[NldpeEvwgs](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function AhyuwZywqh() {return PmjdlInbpc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"orov03J" ascii
    $s3  = "function AhyuwZywqh() {return PmjdlInbpc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"orov03J" ascii
    $s4  = "function IfufiZxzob(DewbkVufpw, DfovpYecxb){CluljGfgso = CluljGfgso * 1; return DewbkVufpw - DfovpYecxb;};" fullword ascii
    $s5  = "var PmjdlInbpc = function VgrwpFioxp() {return FibsjDjzwa[RaqbqJlhnh](\"WScript\"+\".Shell\");}(), SajiaNgjqo = 11;" fullword ascii
    $s6  = "var FibsjDjzwa = this[\"WScript\"];" fullword ascii
    $s7  = "if (SbkeuZjzki[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function JsfznOzlyb(){return IeqdeEvfcg + \"\";};" fullword ascii
    $s9  = "function YxruzDnvgs() {return ((TybetSxwoh == true) && (TybetSxwoh == KqjtmMejuj)) ? 1 : CluljGfgso;};" fullword ascii
    $s10 = "function RaovqEzogb(){return RaqbqJlhnh;};" fullword ascii
    $s11 = "var KftxzAkuwr = false;" fullword ascii
    $s12 = "var HckmqDrprf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function KeeqqVrwmg(MxsfxJeeyl){PmjdlInbpc[\"R\"+\"un\"](MxsfxJeeyl, CluljGfgso, CluljGfgso);};" fullword ascii
    $s14 = "KftxzAkuwr = true;" fullword ascii
    $s15 = "function VoqhmWqgre()" fullword ascii
    $s16 = "function XzsvlYveit(){return 23;};" fullword ascii
    $s17 = "return IfufiZxzob(FnnooMdomk, EhnvzLsaki);" fullword ascii
    $s18 = "function VolenTlbyp(QtqxxZnnzc) {var BeopbNfdop = (1, 2, 3, 4, 5, QtqxxZnnzc); return BeopbNfdop;};" fullword ascii
    $s19 = "KqjtmMejuj = true; " fullword ascii
    $s20 = "var KqjtmMejuj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}