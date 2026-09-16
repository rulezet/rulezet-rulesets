rule sig_20160531_6376f45160c7810e5b405bc1241d6c95 {
  meta:
    description = "datamaliciousorder - file 20160531_6376f45160c7810e5b405bc1241d6c95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343310feac401087a4e8b600cb4eb055db2f1ad270883a9015fb80c421a9cbf8"

  strings:
    $s1  = "var iHKBIK=function(){return WScript.CreateObject(JwWhLGUxWRAThTQN[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "(lQXXPlFZ,0x1,0x0)}function dkXerY(ssSFKrk,TCEodHEYEEpnSf,XLaBdQHtndFHh){var gIoFySzwqoBphn=ssSFKrk.createtextfile(TCEodHEYEEpnS" ascii
    $s3  = "function HhqFjNo(DTIuGVpLTxnwlmCfsnH,MzQVBuszNCwASTSEthdTgwpb){return DTIuGVpLTxnwlmCfsnH.charAt(MzQVBuszNCwASTSEthdTgwpb);}" fullword ascii
    $s4  = "(lQXXPlFZ,0x1,0x0)}function dkXerY(ssSFKrk,TCEodHEYEEpnSf,XLaBdQHtndFHh){var gIoFySzwqoBphn=ssSFKrk.createtextfile(TCEodHEYEEpnS" ascii
    $s5  = "function NYzUPMmqB(CyhRKJnWEFkWW,BBNzSuEqu,IhVPpvpigleSWI){khbWD=CyhRKJnWEFkWW.split(IhVPpvpigleSWI);KwWyYOLsG = JwWhLGUxWRAThTQ" ascii
    $s6  = "function EmlBdIwKHvuZHH(FMhtMqtSGhUSr) {var OZLhRs = dlSwvsXpaWvqPOD.join(JwWhLGUxWRAThTQN[7]);var qOqbBKCtO, HgqeaOFrinGMTQmmPC" ascii
    $s7  = "function EmlBdIwKHvuZHH(FMhtMqtSGhUSr) {var OZLhRs = dlSwvsXpaWvqPOD.join(JwWhLGUxWRAThTQN[7]);var qOqbBKCtO, HgqeaOFrinGMTQmmPC" ascii
    $s8  = "function fNPIMXbtAWs(){return NYzUPMmqB(JwWhLGUxWRAThTQN[13],[0,3,6],JwWhLGUxWRAThTQN[14]);}" fullword ascii
    $s9  = "function ZFSBJKccR(){return NYzUPMmqB(JwWhLGUxWRAThTQN[11],[2,4,8,10],JwWhLGUxWRAThTQN[12]);}" fullword ascii
    $s10 = "var UdWkEivDdIC=function(){return new ActiveXObject(JwWhLGUxWRAThTQN[1]);}();" fullword ascii
    $s11 = "function wJFJwpsm(FCUOFR,QUDPSuXwFIHOvRQo,pyZhHEQpPqDCxY){return String.fromCharCode(FCUOFR,QUDPSuXwFIHOvRQo,pyZhHEQpPqDCxY);}" fullword ascii
    $s12 = "N[0];for(xdAydIwAyKlVC=0;xdAydIwAyKlVC<BBNzSuEqu.length;xdAydIwAyKlVC++) {KwWyYOLsG+=khbWD[BBNzSuEqu[xdAydIwAyKlVC]];}return KwW" ascii
    $s13 = "function fdnoUQzT(){return NYzUPMmqB(JwWhLGUxWRAThTQN[9],[1,5,7],JwWhLGUxWRAThTQN[10]);}" fullword ascii
    $s14 = "function hs(BJelZWxholIwSBGtAIP){return String.fromCharCode(BJelZWxholIwSBGtAIP);}" fullword ascii
    $s15 = " while (VXhIuBIKjQtvTcDeSfTGyPZ < FMhtMqtSGhUSr.length);return sMRQCd;}" fullword ascii
    $s16 = "function oMUESpS(TPRAxNjKCkfIWxDfutndUXQ,dtwqYdYFOXNpP){return String.fromCharCode(TPRAxNjKCkfIWxDfutndUXQ,dtwqYdYFOXNpP);}" fullword ascii
    $s17 = "function fkOQjWahTjd(){return iHKBIK.ExpandEnvironmentStrings(fdnoUQzT())}" fullword ascii
    $s18 = "f,true);gIoFySzwqoBphn.WriteLine(XLaBdQHtndFHh);gIoFySzwqoBphn.Close();}" fullword ascii
    $s19 = "function NYzUPMmqB(CyhRKJnWEFkWW,BBNzSuEqu,IhVPpvpigleSWI){khbWD=CyhRKJnWEFkWW.split(IhVPpvpigleSWI);KwWyYOLsG = JwWhLGUxWRAThTQ" ascii
    $s20 = " 64) sMRQCd += oMUESpS(qOqbBKCtO, HgqeaOFrinGMTQmmPC);else sMRQCd += wJFJwpsm(qOqbBKCtO, HgqeaOFrinGMTQmmPC, XWUYoorLmkwWVmAd);}" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}