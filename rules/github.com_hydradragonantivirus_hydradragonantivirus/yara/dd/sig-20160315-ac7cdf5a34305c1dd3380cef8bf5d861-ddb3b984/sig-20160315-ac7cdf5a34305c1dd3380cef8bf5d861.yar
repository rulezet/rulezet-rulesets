rule sig_20160315_ac7cdf5a34305c1dd3380cef8bf5d861 {
  meta:
    description = "datamaliciousorder - file 20160315_ac7cdf5a34305c1dd3380cef8bf5d861.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92d793ca8c9ff59ed74b4e180ec30988719dc9c30f5a627e14ca6b4da994f468"

  strings:
    $s1  = "var dD = true  , rLJu = qWo[7] + qWo[9] + qWo[11];" fullword ascii
    $s2  = "return kEfVVse[0] + kEfVVse[2] + kEfVVse[4] + \".F\" + kEfVVse[7] + kEfVVse[9] + kEfVVse[12] + kEfVVse[14];" fullword ascii
    $s3  = "var qWo = (\"2.XMLHTTP edLCvlP fEUfx XML ream St cQWNbPJQ AD pqkaKug O FqRy D\").split(\" \");" fullword ascii
    $s4  = "var kEfVVse = IcrHm(\"Sc QmreJFq r xPtrCSKFW ipting kIRgZGq YMW ile zMCbsoNkTHSjyi System Mp KXePA Obj SPmVZw ect NFKxYkl skMQv" ascii
    $s5  = "var kEfVVse = IcrHm(\"Sc QmreJFq r xPtrCSKFW ipting kIRgZGq YMW ile zMCbsoNkTHSjyi System Mp KXePA Obj SPmVZw ect NFKxYkl skMQv" ascii
    $s6  = "mHWHa.open(yUCWj,lUXKy,false);" fullword ascii
    $s7  = "function wlZGAvDwM(MAian) {" fullword ascii
    $s8  = "return rUc.size;" fullword ascii
    $s9  = "return VpiWKgx" fullword ascii
    $s10 = "function Meul(HAwXz,WXgFs) {" fullword ascii
    $s11 = "if (uibfH == 347-147){return true;} else {return false;}" fullword ascii
    $s12 = "function PiGq(zkUox) {" fullword ascii
    $s13 = "function BXbn(VbHeX,kkCbF) {" fullword ascii
    $s14 = "function XWyVCdO(JKsh,HCYIe) {" fullword ascii
    $s15 = "return XWyVCdO(Re,mVTmi[454-448]+mVTmi[185-178]+mVTmi[538-530]);" fullword ascii
    $s16 = "function OvHh(QArCY) {" fullword ascii
    $s17 = "function vrIO(mHWHa,lUXKy,yUCWj) {" fullword ascii
    $s18 = "if (zkUox > 193208-993){return true;} else {return false;}" fullword ascii
    $s19 = "return JdNPV.status;" fullword ascii
    $s20 = "if (J >= xVTSW.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}