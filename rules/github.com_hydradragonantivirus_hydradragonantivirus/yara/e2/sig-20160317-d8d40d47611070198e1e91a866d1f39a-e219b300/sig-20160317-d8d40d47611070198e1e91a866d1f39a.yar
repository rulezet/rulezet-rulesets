rule sig_20160317_d8d40d47611070198e1e91a866d1f39a {
  meta:
    description = "datamaliciousorder - file 20160317_d8d40d47611070198e1e91a866d1f39a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e3e91f75418ef5f044506f783cfcea5b1868bb2df5ec889d0c2c613a2735368"

  strings:
    $s1 = "var Q0 = \"ain!\";var UmfVP = \" ag\";var Cvew = \"\\x2c\\x20\\x74r\\x79\";var tL = \"lease\";var BqBr = \"mPXIYEP\".charAt(1);v" ascii
    $s2 = "z), false);aujnu[(ig) + (HqZ)]();while (aujnu[(rYg) + (WJ) + (d0) + (xgA) + (M) + (zr)] < 4 ) {WScript[(MVOsO) + (Lhl)](Cyft() *" ascii
    $s3 = "(d1) + (d2) + (tAe) + bKEo ? (by) + (lnbwc) : (BtiQp) + (DJ) + (TW) + (Yc);}else{WScript.Echo((BqBr) + (tL) + (Cvew) + (UmfVP) +" ascii
    $s4 = "return RC - gziNk;}var bKEo = false;for (var twwQ = 0; twwQ < Cyft() * 1; twwQ++){" fullword ascii
    $s5 = "}}if (bKEo){eiM = DCo[(NseJT) + (d) + (ap) + (vjnt) + (BNo) + (hKeT) + (JgruJ) + (iqEJY) + (BYTik) + (qmvF)]((G) + (MWVBm) + (e)" ascii
    $s6 = "function K(pnf){DCo[(qAQy)](pnf, 0, 0);};function yo(){return (k) + (OY) + (vKbfs) + (K0) + (QJn) + (Z) + (XDbo) + (OXLVl);};fun" ascii
    $s7 = "ction rq(){return (Lli) + (eLI) + (S) + (ICur) + (Bn);};function Cyft(){return 22;};function GN(){" fullword ascii
    $s8 = "var wtX = new this[(tRya) + (Uh)]();" fullword ascii
    $s9 = "bKEo = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}