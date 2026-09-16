rule sig_20151217_c1458873e6d09629b9510c6e026e60d4 {
  meta:
    description = "datamaliciousorder - file 20151217_c1458873e6d09629b9510c6e026e60d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21158e8a39472f962012312abea70382e23fefd7c868f2b0bc715ebb3ea1ac3a"

  strings:
    $s1  = "function dHHzIUcMbUqTfLjGg(SkmRA){oLWwZwSqjTz= '';AhvocJQLaDD=Math.round((Math.pow(Math.sin(632), 2) + Math.pow(Math.cos(632), 2" ascii
    $s2  = ") - 1));while(true){if (AhvocJQLaDD >= (182+820)/167){break;}AhUFNlHAY[AhvocJQLaDD]=Math.round((Math.pow(Math.sin(994), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(994), 2) - 1)); while(true) { if(AhUFNlHAY[AhvocJQLaDD] > SkmRA[AhvocJQLaDD].length-(-185+803)/618) { break; } if" ascii
    $s4  = "pow(Math.cos(656), 2) - 1)));} AhUFNlHAY[AhvocJQLaDD]++;}AhvocJQLaDD++;} return oLWwZwSqjTz}" fullword ascii
    $s5  = "EdQqztugOEvSQZGNxkCWZnFqgmCoIbSEkFH([SkmRA[AhvocJQLaDD][AhUFNlHAY[AhvocJQLaDD]]], Math.round((Math.pow(Math.sin(656), 2) + Math." ascii
    $s6  = "function dHHzIUcMbUqTfLjGg(SkmRA){oLWwZwSqjTz= '';AhvocJQLaDD=Math.round((Math.pow(Math.sin(632), 2) + Math.pow(Math.cos(632), 2" ascii
    $s7  = "function HoIXShD(vWInINYmQcgLZGqdIHNanyiqSDTayAjxbcLN) {return !sAawnnPqSoI(naLsPLoCWNAbdIb(vWInINYmQcgLZGqdIHNanyiqSDTayAjxbcLN" ascii
    $s8  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s9  = "function GLlJP(zpVYkQWwBeH,AvqWewGQLnLfi,XtlmzUEO){nlKb=zATafaRhEnocfSbVa(zpVYkQWwBeH,AvqWewGQLnLfi);BAAaf=nlKb.toString(XtlmzUE" ascii
    $s10 = "function QfTGxXfRvAQcyjjnAXqEdQqztugOEvSQZGNxkCWZnFqgmCoIbSEkFH(PxnDJeCHPbkTQ,KIJkYwMdogqKmQ){ return AmOzGoW[FPxZXaxb[GLlJP(Pxn" ascii
    $s11 = "function AfPcZvlVljovnnr(cwZfFdOnaqkbUlxPu,EvNEKPNokEsPcpJbWtMbipHHcJBoTYeBlz,pPwXWFTrODdssjQrPwFNLjcjyCRPEvkBnSM){eval(cwZfFdOn" ascii
    $s12 = ",'-','w','D','V','+','c','5','W','X','T','H','0','0','X','_','Y','+','!','8','4','c','Z','`','s','M','b','q','[',':','j',String." ascii
    $s13 = "function X(bnJZuCnKLTiowI,LeKsxYxebAVsx,YChoeAybiab) {bnJZuCnKLTiowI[LeKsxYxebAVsx]=YChoeAybiab;}" fullword ascii
    $s14 = "function HoIXShD(vWInINYmQcgLZGqdIHNanyiqSDTayAjxbcLN) {return !sAawnnPqSoI(naLsPLoCWNAbdIb(vWInINYmQcgLZGqdIHNanyiqSDTayAjxbcLN" ascii
    $s15 = "function GLlJP(zpVYkQWwBeH,AvqWewGQLnLfi,XtlmzUEO){nlKb=zATafaRhEnocfSbVa(zpVYkQWwBeH,AvqWewGQLnLfi);BAAaf=nlKb.toString(XtlmzUE" ascii
    $s16 = "function sAawnnPqSoI(qtSWEKJZzqDPRJ) {return isNaN(qtSWEKJZzqDPRJ);}" fullword ascii
    $s17 = "function zATafaRhEnocfSbVa(MNLcnyTcMO,QQUBZrWPAJ) {return parseInt(MNLcnyTcMO,QQUBZrWPAJ);}" fullword ascii
    $s18 = "O);return BAAaf;}" fullword ascii
    $s19 = "function fbLKnGhaouFk(dxkPmWpcOxDbH) {return isFinite(dxkPmWpcOxDbH);}" fullword ascii
    $s20 = "function AfPcZvlVljovnnr(cwZfFdOnaqkbUlxPu,EvNEKPNokEsPcpJbWtMbipHHcJBoTYeBlz,pPwXWFTrODdssjQrPwFNLjcjyCRPEvkBnSM){eval(cwZfFdOn" ascii

  condition:
    uint16(0) == 0x5046 and
    8 of them
}