rule sig_20160328_e8c013e597b03a7c75f15388083d74b8 {
  meta:
    description = "datamaliciousorder - file 20160328_e8c013e597b03a7c75f15388083d74b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e5306376b51d0977ccbafd2884e420799c136a5fe7375fe72580b1902f77b2a"

  strings:
    $s1  = "function Pzamjkfbjf() {return Qpnzztk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"mYt5ubQ55oLD.exe\";};" fullword ascii
    $s2  = "Dsbnilx[Sctkxx](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Ccpksj](Ulslriy() * 11)} while (Dsbnilx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qpnzztk = function Veiyr() {return WScript[Fyjrqonh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nrygaxy(Udrccemh, Whhjpxt){return Udrccemh - Whhjpxt;};" fullword ascii
    $s6  = "function Ffeerldmr(Xhiifa){Qpnzztk[\"Run\"](Xhiifa, Xzzgdhzpho, Xzzgdhzpho);};" fullword ascii
    $s7  = "function Wvzcy() {return ((Naymptvjs == true) && (Naymptvjs == Lfnpsanbmb)) ? 1 : Xzzgdhzpho;};" fullword ascii
    $s8  = " while (Rdatpeh){" fullword ascii
    $s9  = "function Ulslriy(){return 22;};" fullword ascii
    $s10 = "var Naymptvjs = false;" fullword ascii
    $s11 = "Naymptvjs = true; " fullword ascii
    $s12 = "Lfnpsanbmb = true; " fullword ascii
    $s13 = "function Uzmsyba(){return Fyjrqonh;};" fullword ascii
    $s14 = "return Nrygaxy(Jjylfqm, Kwmjgeyxol);" fullword ascii
    $s15 = "var Piwwhydgfn = new this[\"Date\"]();" fullword ascii
    $s16 = "function Alxtor()" fullword ascii
    $s17 = "var Lfnpsanbmb = false;" fullword ascii
    $s18 = "function Amlphi(Kyhzfgmj) {var Tnbmbv = (1, 2, 3, 4, 5, Kyhzfgmj); return Tnbmbv;};" fullword ascii
    $s19 = "var Bqcxyfbrvw = false;" fullword ascii
    $s20 = "function Thnclso(){return Akepne;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}