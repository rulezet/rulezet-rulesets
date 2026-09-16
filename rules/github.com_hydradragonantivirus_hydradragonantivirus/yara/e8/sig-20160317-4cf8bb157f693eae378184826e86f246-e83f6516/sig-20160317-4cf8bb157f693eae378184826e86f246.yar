rule sig_20160317_4cf8bb157f693eae378184826e86f246 {
  meta:
    description = "datamaliciousorder - file 20160317_4cf8bb157f693eae378184826e86f246.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3a221cd3d808d0ad217592fbe9665b45f1ac7ef3d78fd085938bd1913810017"

  strings:
    $s1 = "var bt = \"gai\\x6e!\";var ixz = \" \\x61\";var Txbc = \"t\\x72y\";var NhI = \"ase,\\x20\";var eGPMO = \"Pl\\x65\";var a0 = \"2" ascii
    $s2 = "(fLEF) + (zYlbU) + (Sfxt) + (vmJ), false);YqD[(Pn) + (ELc) + (rtwZ)]();while (YqD[(lcZqJ) + (NZX) + (ay)] < 4 ) {WScript[(Aqm) +" ascii
    $s3 = ") + (T1) + (Hb) : (ISI) + (CZN) + (xec) + (a0);}else{WScript.Echo((eGPMO) + (NhI) + (Txbc) + (ixz) + (bt));}" fullword ascii
    $s4 = "return cdl - Oskv;}var nZTZn = false;for (var GJ = 0; GJ < 10; GJ++){" fullword ascii
    $s5 = "}}if (nZTZn){fyIBP = yC[(ZggFW) + (Oq) + (ScA) + (qJQ) + (EIS) + (Sk) + (a) + (NI) + (gVFU)]((b) + (ccYr) + (OnPO)) + (F) + (J) " ascii
    $s6 = "+ (dJ);};function oRVS(){return (db) + (wAw) + (gw) + (KZx);};function X(){return 22;};function h(){" fullword ascii
    $s7 = "f) + (Ekqk) + (uWjZ) + (nkRzs) + (FH) + (S));function QT(fZKTA){yC[(TZu)](fZKTA, 0, 0);};function Q(){return (VTO) + (aQ) + (m) " ascii
    $s8 = "var IV = new this[(c)]();" fullword ascii
    $s9 = "nZTZn = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}