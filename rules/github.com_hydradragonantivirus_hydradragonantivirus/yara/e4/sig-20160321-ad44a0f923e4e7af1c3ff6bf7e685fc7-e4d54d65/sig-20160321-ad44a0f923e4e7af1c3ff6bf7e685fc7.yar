rule sig_20160321_ad44a0f923e4e7af1c3ff6bf7e685fc7 {
  meta:
    description = "datamaliciousorder - file 20160321_ad44a0f923e4e7af1c3ff6bf7e685fc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69b43c73f22020bb082aa39a6da07158fb3a716fe2b62f06a3732db430bd713f"

  strings:
    $s1  = "var Co = true  , ZAtV = uZP[7] + uZP[9] + uZP[11];" fullword ascii
    $s2  = "return WScript.CreateObject(acYwm);" fullword ascii
    $s3  = "var Suozz = STiLT(\"mXxiax^EYF^pt.Shell^ujXYAdu^Scri^wDbH^%TE^MP%^\\\\^fnqZTGwgm^qzuTkG^CpxvMdk^Vwnbo\", \"^\");" fullword ascii
    $s4  = "return fZTyMHF[0] + fZTyMHF[2] + fZTyMHF[4] + \".F\" + fZTyMHF[7] + fZTyMHF[9] + fZTyMHF[12] + fZTyMHF[14];" fullword ascii
    $s5  = "var uZP = (\"2.XMLHTTP duRfnjg ZpjVM XML ream St mcoCQeoC AD euxJoxj O zlab D\").split(\" \");" fullword ascii
    $s6  = "anbcZ.open(jzkDp,SFpGq,false);" fullword ascii
    $s7  = "var fZTyMHF = STiLT(JhFwRVjrtd+\" \"+\"System uS aNNia Obj MCshMM ect fsHaQCG yAPTn\", \" \");" fullword ascii
    $s8  = "if(h>=x.length) {break;}" fullword ascii
    $s9  = "function lJmk(yQdGL) {" fullword ascii
    $s10 = "function qEWq(GMzKS) {" fullword ascii
    $s11 = "function JYlhRvfcV(QEpruMHmDCf) {" fullword ascii
    $s12 = "if (GNWfI > 174106-537){return true;} else {return false;}" fullword ascii
    $s13 = "wLf = h; break; " fullword ascii
    $s14 = "if (VPvsW == 662-462){return true;} else {return false;}" fullword ascii
    $s15 = "function ftKyG(zFlxCC) {" fullword ascii
    $s16 = "function IIaV(acYwm) {" fullword ascii
    $s17 = "function XEuL(anbcZ,SFpGq,jzkDp) {" fullword ascii
    $s18 = "function OaJLwZcX(Qmn) {" fullword ascii
    $s19 = "return new ActiveXObject(zFlxCC);" fullword ascii
    $s20 = "return HVMWb.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}