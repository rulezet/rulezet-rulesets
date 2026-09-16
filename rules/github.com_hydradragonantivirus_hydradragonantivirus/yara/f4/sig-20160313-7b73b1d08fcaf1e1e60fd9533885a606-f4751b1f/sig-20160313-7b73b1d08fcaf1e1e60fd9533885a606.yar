rule sig_20160313_7b73b1d08fcaf1e1e60fd9533885a606 {
  meta:
    description = "datamaliciousorder - file 20160313_7b73b1d08fcaf1e1e60fd9533885a606.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc6d142d451c3e1794d1502ce7fa610afb57e133307f707664969104e4d0cd8e"

  strings:
    $s1  = "var nu = true  , xneD = Iec[7] + Iec[9] + Iec[11];" fullword ascii
    $s2  = "return JOxwhqE[0] + JOxwhqE[2] + JOxwhqE[4] + \".F\" + JOxwhqE[7] + JOxwhqE[9] + JOxwhqE[12] + JOxwhqE[14];" fullword ascii
    $s3  = "fTdFA.open(mGkmH,gfaWd,false);" fullword ascii
    $s4  = "var JOxwhqE = \"Sc YFQVMho r wJgTmyBqi ipting SRqBunh hiB ile dpsziFuzJIEWir System SX XLxxH Obj DzMbeV ect MPfNbkA\".split(\" " ascii
    $s5  = "var Iec = (\"2.XMLHTTP MDWgBoN lMTuy XML ream St PwguDNOp AD uuukeMM O KZfD D\").split(\" \");" fullword ascii
    $s6  = "function kQzb(eFtoH) {" fullword ascii
    $s7  = "return uuvieCN(JQ,eLLNJ[355-349]+eLLNJ[417-410]+eLLNJ[498-490]);" fullword ascii
    $s8  = "function RjKdYleJ() {" fullword ascii
    $s9  = "if (ISJzr > 160665-753){return true;} else {return false;}" fullword ascii
    $s10 = "return qzPkT;" fullword ascii
    $s11 = "return jYEkkpL" fullword ascii
    $s12 = "if(y>=l.length) {break;}" fullword ascii
    $s13 = "if (eFtoH == 349-149){return true;} else {return false;}" fullword ascii
    $s14 = "function awsL(IgrWJ) {" fullword ascii
    $s15 = "return YHvn.responseBody;" fullword ascii
    $s16 = "function anOXXEBj(vFt) {" fullword ascii
    $s17 = "return hgDx.ExpandEnvironmentStrings(yKNoD);" fullword ascii
    $s18 = "function nkTX(nSGzw) {" fullword ascii
    $s19 = "if (V >= QmrPO.length) {break;}" fullword ascii
    $s20 = "function vVkx(kvucq,avDev) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}