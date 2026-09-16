rule sig_20151217_213486acbd143cf2e12871d3618ac004 {
  meta:
    description = "datamaliciousorder - file 20151217_213486acbd143cf2e12871d3618ac004.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a77b6faa18706364560a970b5fbcffbe35f37f9841ca5f164b1676dcb0a79d"

  strings:
    $s1  = "th.pow(Math.cos(284), 2) - 1)); while(true) { if(vkBfzgTlB[UoafQIdEXIO] > sMdfz[UoafQIdEXIO].length-(381+491)/872) { break; } if" ascii
    $s2  = "pow(Math.cos(556), 2) - 1)));} vkBfzgTlB[UoafQIdEXIO]++;}UoafQIdEXIO++;} return LKimQBLvIOO}" fullword ascii
    $s3  = ") - 1));while(true){if (UoafQIdEXIO >= (5176+806)/997){break;}vkBfzgTlB[UoafQIdEXIO]=Math.round((Math.pow(Math.sin(284), 2) + Ma" ascii
    $s4  = "function HwnrxXLGKRZvXSmFW(sMdfz){LKimQBLvIOO= '';UoafQIdEXIO=Math.round((Math.pow(Math.sin(460), 2) + Math.pow(Math.cos(460), 2" ascii
    $s5  = "function HwnrxXLGKRZvXSmFW(sMdfz){LKimQBLvIOO= '';UoafQIdEXIO=Math.round((Math.pow(Math.sin(460), 2) + Math.pow(Math.cos(460), 2" ascii
    $s6  = "GCuZWlPHsCJnBrEsDZDjNJFHcuASwCAevuu([sMdfz[UoafQIdEXIO][vkBfzgTlB[UoafQIdEXIO]]], Math.round((Math.pow(Math.sin(556), 2) + Math." ascii
    $s7  = "function EZcDRdA(qGEBNOqAZrgTGbOGkZIEFBezZiIbzmMLpOtI) {return !HsBnDPFcxKt(KjtEUxLOxVQBasG(qGEBNOqAZrgTGbOGkZIEFBezZiIbzmMLpOtI" ascii
    $s8  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s9  = "function KjtEUxLOxVQBasG(EbiWGYshgglVwoVlAew) {return parseFloat(EbiWGYshgglVwoVlAew);}" fullword ascii
    $s10 = "function EZcDRdA(qGEBNOqAZrgTGbOGkZIEFBezZiIbzmMLpOtI) {return !HsBnDPFcxKt(KjtEUxLOxVQBasG(qGEBNOqAZrgTGbOGkZIEFBezZiIbzmMLpOtI" ascii
    $s11 = "function XakpKAddvxNP(NCWWhOnWQiFBq) {return isFinite(NCWWhOnWQiFBq);}" fullword ascii
    $s12 = "function r(DadAyraDIIGT,xoZgqwKhWeEPze){DadAyraDIIGT.push(xoZgqwKhWeEPze);}" fullword ascii
    $s13 = "function HsBnDPFcxKt(UTRdvLfplCuWpz) {return isNaN(UTRdvLfplCuWpz);}" fullword ascii
    $s14 = "function p(EjJyVfGXdwjNEL,TIahELSndAuIf,bYoJcHHGhDc) {EjJyVfGXdwjNEL[TIahELSndAuIf]=bYoJcHHGhDc;}" fullword ascii
    $s15 = "function eLFYg(LcZyxFLjbjm,TwgfwdLoLjpJL,opSHFdvX){wQTS=QUplcCbUeWdhhxklx(LcZyxFLjbjm,TwgfwdLoLjpJL);mmhmm=wQTS.toString(opSHFdv" ascii
    $s16 = "function DGLwuGmjuHtKAlF(spvchRNMwvCitSDZB,MMUFtQhIXajVapOMistsJzBYcbzvZIgakF,vFmXGVDlIVkZzJUJWbYZLFrikLlLekwrDRk){eval(spvchRNM" ascii
    $s17 = "function QUplcCbUeWdhhxklx(tOWYXlpMED,UdUPtTRPan) {return parseInt(tOWYXlpMED,UdUPtTRPan);}" fullword ascii
    $s18 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s19 = "function eLFYg(LcZyxFLjbjm,TwgfwdLoLjpJL,opSHFdvX){wQTS=QUplcCbUeWdhhxklx(LcZyxFLjbjm,TwgfwdLoLjpJL);mmhmm=wQTS.toString(opSHFdv" ascii
    $s20 = "function DGLwuGmjuHtKAlF(spvchRNMwvCitSDZB,MMUFtQhIXajVapOMistsJzBYcbzvZIgakF,vFmXGVDlIVkZzJUJWbYZLFrikLlLekwrDRk){eval(spvchRNM" ascii

  condition:
    uint16(0) == 0x4553 and
    8 of them
}