rule sig_20160315_912d5123b20f315079956c9ac6b14031 {
  meta:
    description = "datamaliciousorder - file 20160315_912d5123b20f315079956c9ac6b14031.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8127e1ca0aa8da7d73eed5cb210a92bd6398c265bcdb355e71bf8c18e286e847"

  strings:
    $s1  = "var thv = (\"2.XMLHTTP bBmwFdu DlDyC XML ream St HLdcoMxL AD ZMRlDUB O lvVZ D\").split(\" \");" fullword ascii
    $s2  = "var sh = true  , heQd = thv[7] + thv[9] + thv[11];" fullword ascii
    $s3  = "return UBNTrzJ[0] + UBNTrzJ[2] + UBNTrzJ[4] + \".F\" + UBNTrzJ[7] + UBNTrzJ[9] + UBNTrzJ[12] + UBNTrzJ[14];" fullword ascii
    $s4  = "var UBNTrzJ = dsUDy(\"Sc fsUUgWk r knPdWNzVr ipting FeIMeyY uuY ile OvMDCNGabEfqcv System gC iORBH Obj XAALZA ect plfzRbm yPjeh" ascii
    $s5  = "var UBNTrzJ = dsUDy(\"Sc fsUUgWk r knPdWNzVr ipting FeIMeyY uuY ile OvMDCNGabEfqcv System gC iORBH Obj XAALZA ect plfzRbm yPjeh" ascii
    $s6  = "AAKim.open(yRKrZ,wzdPY,false);" fullword ascii
    $s7  = "if(f>=d.length) {break;}" fullword ascii
    $s8  = "return nrbbRdz(Sq,KFRpM[409-403]+KFRpM[323-316]+KFRpM[787-779]);" fullword ascii
    $s9  = "function iyRzSAE(PMZc) {" fullword ascii
    $s10 = "function CfUE(HAbbS,GWIKQ) {" fullword ascii
    $s11 = "vtZ = f; break; " fullword ascii
    $s12 = "function LYBP(daAMY) {" fullword ascii
    $s13 = "function elerBZzzc(lizPg) {" fullword ascii
    $s14 = "if (WpTCx > 193732-339){return true;} else {return false;}" fullword ascii
    $s15 = "function JjsRIdLQ() {" fullword ascii
    $s16 = "return kOsOC;" fullword ascii
    $s17 = "function nTfbj(dvSvmX) {" fullword ascii
    $s18 = "return irVg.ExpandEnvironmentStrings(kXPWk);" fullword ascii
    $s19 = "return vtymmpG" fullword ascii
    $s20 = "function ilbA(AkmHM) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}