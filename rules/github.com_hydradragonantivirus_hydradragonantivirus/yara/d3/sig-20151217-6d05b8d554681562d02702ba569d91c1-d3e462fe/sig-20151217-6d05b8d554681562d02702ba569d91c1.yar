rule sig_20151217_6d05b8d554681562d02702ba569d91c1 {
  meta:
    description = "datamaliciousorder - file 20151217_6d05b8d554681562d02702ba569d91c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31dead7f0b8ccbf3798e68d0ae5b3064dd2a03e87bfeb138abd5b8a2f3645c1d"

  strings:
    $s1  = ".pow(Math.cos(3), 2) - 1)); while(true) { if(TMPfObNvV[GDLUCmLCsqw] > kaHiP[GDLUCmLCsqw].length-(-835+954)/119) { break; } if (a" ascii
    $s2  = ") - 1));while(true){if (GDLUCmLCsqw >= (3862+776)/773){break;}TMPfObNvV[GDLUCmLCsqw]=Math.round((Math.pow(Math.sin(3), 2) + Math" ascii
    $s3  = "function PvkqyNLeycIZTHXvd(kaHiP){NOhAgWiKRGs= '';GDLUCmLCsqw=Math.round((Math.pow(Math.sin(758), 2) + Math.pow(Math.cos(758), 2" ascii
    $s4  = "(Math.cos(237), 2) - 1)));} TMPfObNvV[GDLUCmLCsqw]++;}GDLUCmLCsqw++;} return NOhAgWiKRGs}" fullword ascii
    $s5  = "function PvkqyNLeycIZTHXvd(kaHiP){NOhAgWiKRGs= '';GDLUCmLCsqw=Math.round((Math.pow(Math.sin(758), 2) + Math.pow(Math.cos(758), 2" ascii
    $s6  = "function arwYMwV(bAqowJKhYZeMzmNDVzpFdCRAgUNmXigPAwLj) {return !nivhzUnnbzm(MusYEUsbqlZgfsm(bAqowJKhYZeMzmNDVzpFdCRAgUNmXigPAwLj" ascii
    $s7  = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s8  = "X);return zkndj;}" fullword ascii
    $s9  = "function fyfHDKEfNhNWknwOt(SBMdkDeVUI,DzsohmMZnE) {return parseInt(SBMdkDeVUI,DzsohmMZnE);}" fullword ascii
    $s10 = "function CiEkkJPIcJwCpRK(JimkZIUIfPMVGuZRx,IibiZAbHaQvhOYlmsLFPeCzdhngwBkKwXE,NRMdTrvlysVWOeuqnxXlRVpqhGmwDatfZXo){eval(JimkZIUI" ascii
    $s11 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s12 = "function MusYEUsbqlZgfsm(KNNZsJXyWmdjWcSmvOs) {return parseFloat(KNNZsJXyWmdjWcSmvOs);}" fullword ascii
    $s13 = "function CiEkkJPIcJwCpRK(JimkZIUIfPMVGuZRx,IibiZAbHaQvhOYlmsLFPeCzdhngwBkKwXE,NRMdTrvlysVWOeuqnxXlRVpqhGmwDatfZXo){eval(JimkZIUI" ascii
    $s14 = "function ZLNRsbbtdxyenUzBSfhtiyUOKAQjQfQZHfKRbboJmcopQhLgJIrJmi(EPBwGDNOQnQyi,zbErOGoKXhVyok){ return XGWUOAb[xAdVhAth[ubwZe(EPB" ascii
    $s15 = "function F(nSzjoibHTavK,LZCgofNxAQDIvI){nSzjoibHTavK.push(LZCgofNxAQDIvI);}" fullword ascii
    $s16 = "function kvcxZHVeoTBT(BgQduvGvKwvML) {return isFinite(BgQduvGvKwvML);}" fullword ascii
    $s17 = "function nivhzUnnbzm(advgDaTtwSfzsu) {return isNaN(advgDaTtwSfzsu);}" fullword ascii
    $s18 = "function ZLNRsbbtdxyenUzBSfhtiyUOKAQjQfQZHfKRbboJmcopQhLgJIrJmi(EPBwGDNOQnQyi,zbErOGoKXhVyok){ return XGWUOAb[xAdVhAth[ubwZe(EPB" ascii
    $s19 = "function ubwZe(tddpSZyKVjt,ABOiizGkfbzhD,TnXtzOZX){yMeI=fyfHDKEfNhNWknwOt(tddpSZyKVjt,ABOiizGkfbzhD);zkndj=yMeI.toString(TnXtzOZ" ascii
    $s20 = "function ubwZe(tddpSZyKVjt,ABOiizGkfbzhD,TnXtzOZX){yMeI=fyfHDKEfNhNWknwOt(tddpSZyKVjt,ABOiizGkfbzhD);zkndj=yMeI.toString(TnXtzOZ" ascii

  condition:
    uint16(0) == 0x4178 and
    8 of them
}