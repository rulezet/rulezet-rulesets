rule sig_20160324_ea819695c401d719b8d7d5b09af124fa {
  meta:
    description = "datamaliciousorder - file 20160324_ea819695c401d719b8d7d5b09af124fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de87ba7955c6101fd7285070d680d9cece67c34c5241b60e8a8219b8655f7c7b"

  strings:
    $s1  = "function qva(QUB){var _112crap = \"s\"; return \"\" + QUB + \"\";};function NUK(q){var _112crap = \"s\"; return \"\" + q + \"\";" ascii
    $s2  = "Th = \"CreateObject\";var E = function OL() {return WScript[MTh](yM + j + Okf + y);}();var TH = 123213,ON = \"MSXML2.XMLHTTP\";v" ascii
    $s3  = "yO + For(dKf)]();WScript[Tu](iV());var K = new this[U](),w = K[Fn + gtH + yO + yDv(dKf)]();var x = \"T0\";x = rLs(A, Ft);var ih " ascii
    $s4  = " FAD + i + jIK + bi(UVk) + aYq(eKG) + VTO + fb, false);K0[w1]();rMf = \"Sleep\";while (K0[sE + n + xz] < 4 ) {WScript[rMf](iV() " ascii
    $s5  = "(MKm)) + Un + t0 + fm + uem(ZUe) + Lx;}; rBx = zd(); K0 = WScript[MTh](rBx); var qFx = 1; while (qFx){try {K0[osK(arB)](Uh(SOJ)," ascii
    $s6  = ";function bj(){var K = new this[U](),Ft = K[Zd(Fn) + gtH + yO + dKf]();WScript[Tu](iV());var K = new this[U](),A = K[Fn + gtH + " ascii
    $s7  = "wV = 2123213,jAL = 0;function T(d){E[UKf](d, jAL, jAL);};function zd(){return ON;};function rLs(hIt, KR){return hIt - KR;};funct" ascii
    $s8  = "rn ((o == true) && (o == Cb)) ? 1 : jAL;};if (o && BLM() && Cb){function v() {return E[vpA + mHq + og(vmJ) + RtU + bOR](rP + YdX" ascii
    $s9  = "\\x65\",Npe = \"c\\x6cos\";function y0(k){var _112crap = \"s\"; return \"\" + k + \"\";};function oo(EwU){var _112crap = \"s\"; " ascii
    $s10 = "\"QeH\";ih = rLs(w, A);return rLs(x, ih);}var o = false,Cb = false;for (var Nrv = jAL; Nrv < iV() * 1; Nrv++){if (bj() != jAL){o" ascii
    $s11 = ";var P0 = \"Re\\x73p\\x6f\";function M0(s){var _112crap = \"s\"; return \"\" + s + \"\";};var Vb = \"\\x65\",Te = \"w\\x72it\";v" ascii
    $s12 = "wU + \"\";};function ih0(tz){var _112crap = \"s\"; return \"\" + tz + \"\";};var QO = \"l\\x65\",i0 = \"\\x54oF\\x69\";var kB = " ascii
    $s13 = "1 = \"\\x73end\";function bi(c){var _112crap = \"s\"; return \"\" + c + \"\";};function aYq(ne){var _112crap = \"s\"; return \"" ascii
    $s14 = "eturn \"\" + z + \"\";};function yDv(t){var _112crap = \"s\"; return \"\" + t + \"\";};var dKf = \"o\\x6eds\",yO = \"li\\x73ec\"" ascii
    $s15 = "12crap = \"s\"; return \"\" + A0 + \"\";};var Lx = \"e\\x78e\",ZUe = \"HCz\\x2e\";var fm = \"6\\x38Kr\",t0 = \"\\x47C\\x54Z\";va" ascii
    $s16 = " \"\\x44at\\x65\",Tu = \"\\x53l\\x65ep\";function Zd(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};function For(z){var _11" ascii
    $s17 = "e\",in0 = \"\\x6fpe\\x6e\";function l0(Xw){var _112crap = \"s\"; return \"\" + Xw + \"\";};var FVE = \"e\\x61m\",JD = \"B\\x2eS" ascii
    $s18 = "x74\\x70\";function Uh(xWf){var _112crap = \"s\"; return \"\" + xWf + \"\";};var SOJ = \"\\x47\\x45\\x54\";function osK(j1){var " ascii
    $s19 = " \"ADO\\x44\";function DLN(B){var _112crap = \"s\"; return \"\" + B + \"\";};var jHj = \"\\x61\",HWr = \"af\\x64af\";var W = \"a" ascii
    $s20 = "nction YdX(gs){var _112crap = \"s\"; return \"\" + gs + \"\";};var MKm = \"\\x25/\",rP = \"%\\x54EMP\";function og(uk){var _112c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}