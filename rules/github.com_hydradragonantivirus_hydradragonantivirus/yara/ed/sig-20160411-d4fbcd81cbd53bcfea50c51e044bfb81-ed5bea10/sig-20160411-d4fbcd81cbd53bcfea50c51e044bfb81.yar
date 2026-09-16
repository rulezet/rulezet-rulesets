rule sig_20160411_d4fbcd81cbd53bcfea50c51e044bfb81 {
  meta:
    description = "datamaliciousorder - file 20160411_d4fbcd81cbd53bcfea50c51e044bfb81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4f8c8db6db472f2a29b049b51dfa399e125bbf87f08d9bb89034d6854f54e2f"

  strings:
    $s1  = "return hBneWAC[0] + hBneWAC[2] + hBneWAC[4] + \".F\" + hBneWAC[7] + hBneWAC[9] + hBneWAC[12] + hBneWAC[14];" fullword ascii
    $s2  = "var EK = true  , MVNQ = pVv[7] + pVv[9] + pVv[11];" fullword ascii
    $s3  = "var pVv = (\"2.XMLHTTP nMYvdPR rJInq XML ream St ZNDiRurW AD SuPzwuQ O gIYc D\").split(\" \");" fullword ascii
    $s4  = "gHQC.open(esfjt,NQbhx,false);" fullword ascii
    $s5  = "if(i>=P.length) {break;}" fullword ascii
    $s6  = "function vAkX(qPXWu) {" fullword ascii
    $s7  = "function REsL(VWqPo,NQbhx,esfjt) {" fullword ascii
    $s8  = "if (gptbX == 365-165){return true;} else {return false;}" fullword ascii
    $s9  = "function CewU(yZDkz,UhbRk) {" fullword ascii
    $s10 = "function opmP(eJicm) {" fullword ascii
    $s11 = "if (C >= qPXWu.length) {break;}" fullword ascii
    $s12 = "function sNqh(CfdOS,DOjTw) {" fullword ascii
    $s13 = "function PYMeqF(ToddfdZ) {" fullword ascii
    $s14 = "return TJBnxJr;" fullword ascii
    $s15 = "return GoaSjov[0];" fullword ascii
    $s16 = "function oDAsmKlz(TEo) {" fullword ascii
    $s17 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s18 = "function gCGTL(cOZjNb) {" fullword ascii
    $s19 = "WzK = i; break; " fullword ascii
    $s20 = "function jrcEO(NKnVUN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}