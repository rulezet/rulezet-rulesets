rule sig_20151217_72a2745824820c8cf9f22fdabdf72c56 {
  meta:
    description = "datamaliciousorder - file 20151217_72a2745824820c8cf9f22fdabdf72c56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "192d5d14d628314a92d6760ce22eac9f9b37f21e23caf60c43eae90e8a1e2db8"

  strings:
    $s1  = ") - 1));while(true){if (LapYuGVkulV >= (-18+588)/95){break;}itNlEQwFN[LapYuGVkulV]=Math.round((Math.pow(Math.sin(393), 2) + Math" ascii
    $s2  = "function UhhNgmTVemwjYZvkd(Aduwp){jiafUDcknCj= '';LapYuGVkulV=Math.round((Math.pow(Math.sin(860), 2) + Math.pow(Math.cos(860), 2" ascii
    $s3  = ".pow(Math.cos(393), 2) - 1)); while(true) { if(itNlEQwFN[LapYuGVkulV] > Aduwp[LapYuGVkulV].length-(-141+677)/536) { break; } if " ascii
    $s4  = "ow(Math.cos(377), 2) - 1)));} itNlEQwFN[LapYuGVkulV]++;}LapYuGVkulV++;} return jiafUDcknCj}" fullword ascii
    $s5  = "function UhhNgmTVemwjYZvkd(Aduwp){jiafUDcknCj= '';LapYuGVkulV=Math.round((Math.pow(Math.sin(860), 2) + Math.pow(Math.cos(860), 2" ascii
    $s6  = "function GxfiIhN(PeslKlUtldDTNqaeYMqSEHwAquKQIAKvqyiF) {return !QLiwRWYyjyd(DKICmXzkYMLASEm(PeslKlUtldDTNqaeYMqSEHwAquKQIAKvqyiF" ascii
    $s7  = "function b(HwDtsXkKTepgnP,UXYMEWoTfzVKA,iGRxPuVFwwT) {HwDtsXkKTepgnP[UXYMEWoTfzVKA]=iGRxPuVFwwT;}" fullword ascii
    $s8  = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s9  = "function IYMeAwTNVhBGxDd(DIKukehoifzZBbPDv,ywQmhPPPIUVAyFBrbCVfCJMAjpZallPShF,ivawUxSCyqvMoJUOomjwgjlQVbstZXnaPhN){eval(DIKukeho" ascii
    $s10 = "function n(bEPbHioOAlNJ,CjFvWLRlTwPndt){bEPbHioOAlNJ.push(CjFvWLRlTwPndt);}" fullword ascii
    $s11 = "function TkmmPcExEPdA(ItLRwFAEjYAUV) {return isFinite(ItLRwFAEjYAUV);}" fullword ascii
    $s12 = "B);return oYPHu;}" fullword ascii
    $s13 = "function QLiwRWYyjyd(fcYmpSvmbFpDzL) {return isNaN(fcYmpSvmbFpDzL);}" fullword ascii
    $s14 = "function GxfiIhN(PeslKlUtldDTNqaeYMqSEHwAquKQIAKvqyiF) {return !QLiwRWYyjyd(DKICmXzkYMLASEm(PeslKlUtldDTNqaeYMqSEHwAquKQIAKvqyiF" ascii
    $s15 = "function NErZegCiqorYlSZcOonOnZWlcldicXwwHLCJgKXNcGDTqSObFBRULs(iUoedZYGVFKpx,XLNOwbtIxXvSjS){ return PuFdosW[UUJQGnyl[ALJYq(iUo" ascii
    $s16 = "function ALJYq(RQhgACDVrZi,uKKFsJDPuxxGt,uvrLVZPB){LdXt=mNOVfaFFnIdaEptUs(RQhgACDVrZi,uKKFsJDPuxxGt);oYPHu=LdXt.toString(uvrLVZP" ascii
    $s17 = "function DKICmXzkYMLASEm(ltSwxYzuZhlopdugZEI) {return parseFloat(ltSwxYzuZhlopdugZEI);}" fullword ascii
    $s18 = "function ALJYq(RQhgACDVrZi,uKKFsJDPuxxGt,uvrLVZPB){LdXt=mNOVfaFFnIdaEptUs(RQhgACDVrZi,uKKFsJDPuxxGt);oYPHu=LdXt.toString(uvrLVZP" ascii
    $s19 = "function NErZegCiqorYlSZcOonOnZWlcldicXwwHLCJgKXNcGDTqSObFBRULs(iUoedZYGVFKpx,XLNOwbtIxXvSjS){ return PuFdosW[UUJQGnyl[ALJYq(iUo" ascii
    $s20 = "function IYMeAwTNVhBGxDd(DIKukehoifzZBbPDv,ywQmhPPPIUVAyFBrbCVfCJMAjpZallPShF,ivawUxSCyqvMoJUOomjwgjlQVbstZXnaPhN){eval(DIKukeho" ascii

  condition:
    uint16(0) == 0x5555 and
    8 of them
}