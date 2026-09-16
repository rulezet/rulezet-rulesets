rule sig_20160315_de40d686c6679c713664154cb67566a8 {
  meta:
    description = "datamaliciousorder - file 20160315_de40d686c6679c713664154cb67566a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7194e7f0c3516e65b4ac9dae10b9d29f1f5c557b8c02d0425f5169d6a60b6ec1"

  strings:
    $s1  = "var fn = true  , Lugp = gBZ[7] + gBZ[9] + gBZ[11];" fullword ascii
    $s2  = "return yFFDAox[0] + yFFDAox[2] + yFFDAox[4] + \".F\" + yFFDAox[7] + yFFDAox[9] + yFFDAox[12] + yFFDAox[14];" fullword ascii
    $s3  = "var gBZ = (\"2.XMLHTTP BEVohUE uMyCs XML ream St GanNuQON AD mlzVQHh O mNxj D\").split(\" \");" fullword ascii
    $s4  = "var yFFDAox = CGfcc(\"Sc XGjwChq r fYLUbpqSH ipting PLwMusI Zkw ile onLURFhzKqeCMY System PK ASOXQ Obj LUJlmY ect PqaVCVI BopSN" ascii
    $s5  = "OfMoT.open(NuaoB,eIXJE,false);" fullword ascii
    $s6  = "var yFFDAox = CGfcc(\"Sc XGjwChq r fYLUbpqSH ipting PLwMusI Zkw ile onLURFhzKqeCMY System PK ASOXQ Obj LUJlmY ect PqaVCVI BopSN" ascii
    $s7  = "return JOg.size;" fullword ascii
    $s8  = "function wxgaa(uJsOvx) {" fullword ascii
    $s9  = "function WNHgmMC(kvLt,ZcKfD) {" fullword ascii
    $s10 = "function BPfk(sHNfz) {" fullword ascii
    $s11 = "function mylR(xxzLa) {" fullword ascii
    $s12 = "if(K>=n.length) {break;}" fullword ascii
    $s13 = "function KYKuyRxyi(nIsnW) {" fullword ascii
    $s14 = "function ehbr(QVlzU) {" fullword ascii
    $s15 = "function sFhe(OidjN) {" fullword ascii
    $s16 = "function cmVXybA(OAdF) {" fullword ascii
    $s17 = "return gni.split(TfKlM);" fullword ascii
    $s18 = "return WNHgmMC(Hi,CZXgf[122-116]+CZXgf[136-129]+CZXgf[258-250]);" fullword ascii
    $s19 = "function sASVFhLG(JOg) {" fullword ascii
    $s20 = "if (OidjN > 187424-423){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}