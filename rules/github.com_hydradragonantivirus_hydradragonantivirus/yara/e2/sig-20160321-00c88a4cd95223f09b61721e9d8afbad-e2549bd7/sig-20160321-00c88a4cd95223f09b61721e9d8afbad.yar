rule sig_20160321_00c88a4cd95223f09b61721e9d8afbad {
  meta:
    description = "datamaliciousorder - file 20160321_00c88a4cd95223f09b61721e9d8afbad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec2880f16ae10950185cee16a43555873dc4302ddb40586b3910d72445cb22fc"

  strings:
    $s1  = "var ihKdNkg = yTMpO(xQkHJsaRoA+\" \"+\"System kX wWRTe Obj wxDers ect DHldCeM WDeNq\", \" \");" fullword ascii
    $s2  = "return WScript.CreateObject(oQPCk);" fullword ascii
    $s3  = "var cZ = true  , QwNK = nOJ[7] + nOJ[9] + nOJ[11];" fullword ascii
    $s4  = "function KatzISil(rCs) {" fullword ascii
    $s5  = "return ihKdNkg[0] + ihKdNkg[2] + ihKdNkg[4] + \".F\" + ihKdNkg[7] + ihKdNkg[9] + ihKdNkg[12] + ihKdNkg[14];" fullword ascii
    $s6  = "function yTMpO(CNF,gaPDS) {" fullword ascii
    $s7  = "YzXno.open(dcFCk,mylww,false);" fullword ascii
    $s8  = "var nOJ = (\"2.XMLHTTP pIqIBlC TYizn XML ream St ggdDyiuv AD QgzFKkL O CdBs D\").split(\" \");" fullword ascii
    $s9  = "return oMbQNz.position=189-189;" fullword ascii
    $s10 = "function tnyF(bmcgj) {" fullword ascii
    $s11 = "Wdw = a; break; " fullword ascii
    $s12 = "if(a>=s.length) {break;}" fullword ascii
    $s13 = "return LpKjFvk(KK,PqbFr[631-625]+PqbFr[350-343]+PqbFr[279-271]);" fullword ascii
    $s14 = "function xTdtBlXX(XHXl) {" fullword ascii
    $s15 = "function NUvZ(HBLZV) {" fullword ascii
    $s16 = "function MpJC(bBdln,FTgNJ) {" fullword ascii
    $s17 = "return CNF.split(gaPDS);" fullword ascii
    $s18 = "function Nekoq(oMbQNz) {" fullword ascii
    $s19 = "return pkUh[alSxTt[0]];" fullword ascii
    $s20 = "return JQNFq.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}