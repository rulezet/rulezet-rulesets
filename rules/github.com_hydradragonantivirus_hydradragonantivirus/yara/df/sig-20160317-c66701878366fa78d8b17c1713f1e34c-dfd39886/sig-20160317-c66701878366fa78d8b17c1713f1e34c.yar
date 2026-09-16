rule sig_20160317_c66701878366fa78d8b17c1713f1e34c {
  meta:
    description = "datamaliciousorder - file 20160317_c66701878366fa78d8b17c1713f1e34c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e682b5ee4d5ff9131bd83d6f902aeda50bacddfa6c4bb553b86474fb3d002eb9"

  strings:
    $s1 = "var cq = \"ain!\";var OEbh = \"\\x20\\x61\\x67\";var Sl = \"try\";var osTzQ = \"\\x61se\\x2c \";var FbT = \"e\";var Un = \"I7blS" ascii
    $s2 = "}}if (BbrDI){cW = b[(MK) + (CLrY) + (l) + (cve) + (g) + (AP) + (xt)]((uhbX) + (yNBZ) + (TRpQ) + (BK)) + (vin) + (ndQZZ) + (Cen) " ascii
    $s3 = " BbrDI ? (j) + (VbQS) + (Q) : (yTji) + (HOs) + (KuEf) + (fVGi);}else{WScript.Echo((Jaixc) + (Un) + (FbT) + (osTzQ) + (Sl) + (OEb" ascii
    $s4 = "return sI - bn;}var BbrDI = false;for (var VHzEK = 0; VHzEK < A() * 1; VHzEK++){" fullword ascii
    $s5 = "TAOi) + (z) + (dsh) + (VD) + (PGq) + (A0) + (G0) + (kLr) + (G1) + (G2), false);hFr[(z0) + (L)]();while (hFr[(IeU) + (Jkc) + (pqh" ascii
    $s6 = " (bKJ);};function B(){return (dq) + (fx) + (PrZO) + (JcyY);};function A(){return 22;};function cGTFQ(){" fullword ascii
    $s7 = "BbrDI = true;" fullword ascii
    $s8 = "var UZsjn = new this[(aQkCs)]();" fullword ascii
    $s9 = "+ (sYjU) + (d) + (Bn));function RdO(G){b[(kzXh)](G, 0, 0);};function LE(){return (Jo) + (x) + (dNr) + (azMJn) + (LvM) + (caBt) +" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}