rule sig_20160317_db436c0c79049dafc9e3e860f29da769 {
  meta:
    description = "datamaliciousorder - file 20160317_db436c0c79049dafc9e3e860f29da769.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c517ad30e966914a8832b6ccff32a3b610c7c8dc10cde6c09000e00928216e91"

  strings:
    $s1 = "var HP = \"a\\x69n!\";var VxaZe = \"g\";var L = \"y \\x61\";var qGV = \"e\\x2c\\x20\\x74r\";var AJc = \"Pleas\";var a2 = \"1\\x3" ascii
    $s2 = "false);yOP[(uuduL)]();while (yOP[(nOs) + (a1) + (ed) + (mo) + (fRBR)] < 4 ) {WScript[(zsw) + (Scgtf)](G() * 10)};wfFH = WScript[" ascii
    $s3 = "(a2);}else{WScript.Echo((AJc) + (qGV) + (L) + (VxaZe) + (HP));}" fullword ascii
    $s4 = "}}if (Serh){bLfqD = b[(Jd) + (c) + (diB) + (NE) + (kxQWh) + (cl) + (Dhyvj) + (so)]((KAZOm) + (QHeKF) + (j) + (tdg)) + (TUAm) + (" ascii
    $s5 = "return GT - rCuq;}var Serh = false;for (var NXfav = 0; NXfav < G() * 1; NXfav++){" fullword ascii
    $s6 = "+ (tB)]((hHT) + (g) + (r) + (sv) + (HTt));function YkjO(knSee){b[(aAWJ)](knSee, 0, 0);};function uAIW(){return (gBlR) + (DGN) + " ascii
    $s7 = "(a0) + (ztEX);};function Gn(){return (O) + (Zjmb) + (e0) + (iNYg) + (tB);};function G(){return 22;};function zYg(){" fullword ascii
    $s8 = "var l = new this[(UO) + (SS) + (yWZu)]();" fullword ascii
    $s9 = "Serh = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}