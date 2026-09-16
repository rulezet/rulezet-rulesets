rule sig_20160323_9282141de4b6d10443b99e489d3ae1a5 {
  meta:
    description = "datamaliciousorder - file 20160323_9282141de4b6d10443b99e489d3ae1a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb49ab01dd38356ed9165780c96fc6147192fd12d201deb4cbd798aaf5d60244"

  strings:
    $s1  = "return WScript.CreateObject(sDqNi);" fullword ascii
    $s2  = "return XDyipuJ[0] + XDyipuJ[2] + XDyipuJ[4] + \".F\" + XDyipuJ[7] + XDyipuJ[9] + XDyipuJ[12] + XDyipuJ[14];" fullword ascii
    $s3  = "var mu = true  , nOuZ = TjX[7] + TjX[9] + TjX[11];" fullword ascii
    $s4  = "var TjX = (\"2.XMLHTTP OzAnBGw XxEsK XML ream St ZWIKJlkW AD GCoHoGf O DMyb D\").split(\" \");" fullword ascii
    $s5  = "yViN.open(yjkbx,vawqD,false);" fullword ascii
    $s6  = "var XDyipuJ = kFfnX(OcoCwNkaow+\" \"+\"System yj WUsGy Obj Daghtx ect qIzFHAi rfiwz\", \" \");" fullword ascii
    $s7  = "function fSJuXLVJj(FkiGbufsHsq) {" fullword ascii
    $s8  = "function RoUV(RhjTP,vawqD,yjkbx) {" fullword ascii
    $s9  = "FVn = q; break; " fullword ascii
    $s10 = "if (NkeAx > 169528-857){return true;} else {return false;}" fullword ascii
    $s11 = "function dPtH(CqDJv) {" fullword ascii
    $s12 = "return vUoS[WGeDHX[0]];" fullword ascii
    $s13 = "function HXUz(NkeAx) {" fullword ascii
    $s14 = "return Dac.size;" fullword ascii
    $s15 = "return ktlMOV/*wweDO1y2Jmw73udEefqwFZWGf*/.position=459-459;" fullword ascii
    $s16 = "return JGUu.ExpandEnvironmentStrings(yLvDx);" fullword ascii
    $s17 = "if(q>=D.length) {break;}" fullword ascii
    $s18 = "function xhyvR(ktlMOV) {" fullword ascii
    $s19 = "if (GituH == 485-285){return true;} else {return false;}" fullword ascii
    $s20 = "return jONwsRW(pL,SKagi[525-519]+SKagi[893-886]+SKagi[391-383]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}