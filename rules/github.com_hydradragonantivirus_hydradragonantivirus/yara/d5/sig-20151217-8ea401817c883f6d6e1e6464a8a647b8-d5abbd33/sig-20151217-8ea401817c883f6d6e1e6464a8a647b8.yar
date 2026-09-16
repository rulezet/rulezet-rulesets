rule sig_20151217_8ea401817c883f6d6e1e6464a8a647b8 {
  meta:
    description = "datamaliciousorder - file 20151217_8ea401817c883f6d6e1e6464a8a647b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f6bc2fc41c0e4f0cb0e2bc15f84ea8f8fce7005c3b15ebf4b1559b6ec2ecabb"

  strings:
    $s1  = "th.pow(Math.cos(349), 2) - 1)); while(true) { if(BruhWoqnl[BtnPdMrUQsV] > DYEgX[BtnPdMrUQsV].length-(816+92)/908) { break; } if " ascii
    $s2  = "w(Math.cos(785), 2) - 1)));} BruhWoqnl[BtnPdMrUQsV]++;}BtnPdMrUQsV++;} return NxinuENqxZd}" fullword ascii
    $s3  = ") - 1));while(true){if (BtnPdMrUQsV >= (2104+386)/415){break;}BruhWoqnl[BtnPdMrUQsV]=Math.round((Math.pow(Math.sin(349), 2) + Ma" ascii
    $s4  = "function rPqlFLSVOnAHKteyF(DYEgX){NxinuENqxZd= '';BtnPdMrUQsV=Math.round((Math.pow(Math.sin(718), 2) + Math.pow(Math.cos(718), 2" ascii
    $s5  = "function rPqlFLSVOnAHKteyF(DYEgX){NxinuENqxZd= '';BtnPdMrUQsV=Math.round((Math.pow(Math.sin(718), 2) + Math.pow(Math.cos(718), 2" ascii
    $s6  = "function kLWkhMZ(KjLHBxtBDXCSnCMjJfZZvCFnizxCTZTOYbcn) {return !fBrdAwVMiRn(khwtOllcIJlwKTA(KjLHBxtBDXCSnCMjJfZZvCFnizxCTZTOYbcn" ascii
    $s7  = "function vxZYwaIiDCBMprifb(OwEuajeqLF,ydXKtYNLxB) {return parseInt(OwEuajeqLF,ydXKtYNLxB);}" fullword ascii
    $s8  = "function BQYEl(UMrqKeTQHym,PgtgYRcxgKWDa,QvudrSIp){rYtg=vxZYwaIiDCBMprifb(UMrqKeTQHym,PgtgYRcxgKWDa);GgsPk=rYtg.toString(QvudrSI" ascii
    $s9  = "function kLWkhMZ(KjLHBxtBDXCSnCMjJfZZvCFnizxCTZTOYbcn) {return !fBrdAwVMiRn(khwtOllcIJlwKTA(KjLHBxtBDXCSnCMjJfZZvCFnizxCTZTOYbcn" ascii
    $s10 = "function p(DswOEYgmKgos,ZaRAWMXMMqGBqB){DswOEYgmKgos.push(ZaRAWMXMMqGBqB);}" fullword ascii
    $s11 = "function vMbgsXjnqazYwCYDaKkZneRSGyLNCYSijibEscbqNfJRpjXMYzlHPD(vodTgrdHEqrfp,OBosMLtMvOVntR){ return dZdZeNA[TlSvoUHz[BQYEl(vod" ascii
    $s12 = "function ExQuDeHQmMHd(SCGYnvwDMrpLM) {return isFinite(SCGYnvwDMrpLM);}" fullword ascii
    $s13 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s14 = "function BQYEl(UMrqKeTQHym,PgtgYRcxgKWDa,QvudrSIp){rYtg=vxZYwaIiDCBMprifb(UMrqKeTQHym,PgtgYRcxgKWDa);GgsPk=rYtg.toString(QvudrSI" ascii
    $s15 = "function vMbgsXjnqazYwCYDaKkZneRSGyLNCYSijibEscbqNfJRpjXMYzlHPD(vodTgrdHEqrfp,OBosMLtMvOVntR){ return dZdZeNA[TlSvoUHz[BQYEl(vod" ascii
    $s16 = "function NGitWXnMFnVjxfR(LKkDVvGgFOuAeGmbP,kkBfIgCSNlCLnYqEjLUQcJAobTPSUKbIHQ,DYGIYxDJZcdzbxzBBrWnutVthezPFgqiZZu){eval(LKkDVvGg" ascii
    $s17 = "function fBrdAwVMiRn(PfYVWDYdCbkxMj) {return isNaN(PfYVWDYdCbkxMj);}" fullword ascii
    $s18 = "function khwtOllcIJlwKTA(SamJrcrWlxlTnCFePLU) {return parseFloat(SamJrcrWlxlTnCFePLU);}" fullword ascii
    $s19 = "p);return GgsPk;}" fullword ascii
    $s20 = "function N(ZllzgUASPBXmTP,EDSKWkqTmEnmQ,RZdmxvVhDHg) {ZllzgUASPBXmTP[EDSKWkqTmEnmQ]=RZdmxvVhDHg;}" fullword ascii

  condition:
    uint16(0) == 0x6c54 and
    8 of them
}