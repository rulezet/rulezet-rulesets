rule sig_20160321_d5a64469cc9c1d191722a0fbaec57544 {
  meta:
    description = "datamaliciousorder - file 20160321_d5a64469cc9c1d191722a0fbaec57544.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "373fea473614cb16f98f877e4b6438c985afa59d84b235ba7884d5eaaff287b2"

  strings:
    $s1  = "return WScript.CreateObject(mjKpI);" fullword ascii
    $s2  = "var dP = true  , TtjT = Fcd[7] + Fcd[9] + Fcd[11];" fullword ascii
    $s3  = "return ekxZzkw[0] + ekxZzkw[2] + ekxZzkw[4] + \".F\" + ekxZzkw[7] + ekxZzkw[9] + ekxZzkw[12] + ekxZzkw[14];" fullword ascii
    $s4  = "var ekxZzkw = hclyJ(vOnXdJVTXr+\" \"+\"System Lg dTOXO Obj XOJgeI ect SdhcHyS kfcfc\", \" \");" fullword ascii
    $s5  = "var Fcd = (\"2.XMLHTTP jSReFvV Nsdkx XML ream St lynlTWmO AD yixLYaw O BsjH D\").split(\" \");" fullword ascii
    $s6  = "XpkcZ.open(cLaVj,PFJhT,false);" fullword ascii
    $s7  = "if(V>=x.length) {break;}" fullword ascii
    $s8  = "if (u >= cHtYB.length) {break;}" fullword ascii
    $s9  = "return VwG.size;" fullword ascii
    $s10 = "function BSnHjmf(YZtn) {" fullword ascii
    $s11 = "function xdEa(ZiFVL,BIITH) {" fullword ascii
    $s12 = "function Zeoq(ujSLJ) {" fullword ascii
    $s13 = "function NNTVRRhe(VwG) {" fullword ascii
    $s14 = "if (ujSLJ > 188717-354){return true;} else {return false;}" fullword ascii
    $s15 = "function mnlWJ(uvnanG) {" fullword ascii
    $s16 = "Ilz = V; break; " fullword ascii
    $s17 = "return ObPW.ExpandEnvironmentStrings(NqQgD);" fullword ascii
    $s18 = "return obmJl.status;" fullword ascii
    $s19 = "function WMdj(cHtYB) {" fullword ascii
    $s20 = "function qbHK(XpkcZ,PFJhT,cLaVj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}