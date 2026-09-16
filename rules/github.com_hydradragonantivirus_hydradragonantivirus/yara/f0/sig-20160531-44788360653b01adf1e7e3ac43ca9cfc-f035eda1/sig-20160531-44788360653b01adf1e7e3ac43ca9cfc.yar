rule sig_20160531_44788360653b01adf1e7e3ac43ca9cfc {
  meta:
    description = "datamaliciousorder - file 20160531_44788360653b01adf1e7e3ac43ca9cfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09265949fdd9a6c42b7d1fa78c46277ad2fdc4dc2db49c0939b89577d41f6ca"

  strings:
    $s1  = "var JftNOuNfS=function(){return WScript.CreateObject(wRhUYZjzzSMZuvBmkqrmi[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function zLgbJUwClCjnWJZN(lXvJLqYvutE,vYMOSzyyMIJnvAiyhdnhpYh){return lXvJLqYvutE.charAt(vYMOSzyyMIJnvAiyhdnhpYh);}" fullword ascii
    $s3  = "function wWzjAZWQBxEGY(){return JftNOuNfS.ExpandEnvironmentStrings(QFtzTcoWGeUe())}" fullword ascii
    $s4  = "function UwrUFSwmXUwYmkKVQxGhQY(EKbrfIWjgrEIdCzRRFxEgY,dvtVNB,rZIao){return String.fromCharCode(EKbrfIWjgrEIdCzRRFxEgY,dvtVNB,rZ" ascii
    $s5  = "function mRMbfikx(eZDrEDQqRmionBFKAuMhmF,zhUrcGxsNWrjGNhwqPNeOL){return eZDrEDQqRmionBFKAuMhmF.indexOf(zhUrcGxsNWrjGNhwqPNeOL);}" ascii
    $s6  = "function kg(abtPAnHtiexQfpQqQjkHmqui){return String.fromCharCode(abtPAnHtiexQfpQqQjkHmqui);}" fullword ascii
    $s7  = "function OcJYqXmkbOCrT(){return eIqSxMmttJV(wRhUYZjzzSMZuvBmkqrmi[11],[2,4,8,10],wRhUYZjzzSMZuvBmkqrmi[12]);}" fullword ascii
    $s8  = "jtKEKF == 64) ZssduvArYVQrxAXDuNI += fOIhSXUWksDXMxHdV(ebQBtHOnKZ, nMbGkXZOpXHo);else ZssduvArYVQrxAXDuNI += UwrUFSwmXUwYmkKVQxG" ascii
    $s9  = "function fOIhSXUWksDXMxHdV(GrroATKDJTYGQEsBZBmsN,ozsjgOqibyfpmdNvvVlhMeG){return String.fromCharCode(GrroATKDJTYGQEsBZBmsN,ozsjg" ascii
    $s10 = "(PFlKEbTfdzz,0x1,0x0)}function MLgFqMIGF(wfTJndTc,RRxgwzvzVuvV,uHZEOAW){var miFJpR=wfTJndTc.createtextfile(RRxgwzvzVuvV,true);mi" ascii
    $s11 = "function fOIhSXUWksDXMxHdV(GrroATKDJTYGQEsBZBmsN,ozsjgOqibyfpmdNvvVlhMeG){return String.fromCharCode(GrroATKDJTYGQEsBZBmsN,ozsjg" ascii
    $s12 = "function eIqSxMmttJV(zgtEO,PMHEYnWAdt,PiNhiE){dnviJK=zgtEO.split(PiNhiE);pXwTOzWhy = wRhUYZjzzSMZuvBmkqrmi[0];for(lLeoMPMFC=0;lL" ascii
    $s13 = "function eIqSxMmttJV(zgtEO,PMHEYnWAdt,PiNhiE){dnviJK=zgtEO.split(PiNhiE);pXwTOzWhy = wRhUYZjzzSMZuvBmkqrmi[0];for(lLeoMPMFC=0;lL" ascii
    $s14 = "hQY(ebQBtHOnKZ, nMbGkXZOpXHo, NrCsKclJsRQUopo);} while (abJHEwGcOO < JoZAdYimEYTkS.length);return ZssduvArYVQrxAXDuNI;}" fullword ascii
    $s15 = "eoMPMFC<PMHEYnWAdt.length;lLeoMPMFC++) {pXwTOzWhy+=dnviJK[PMHEYnWAdt[lLeoMPMFC]];}return pXwTOzWhy.substring(3,pXwTOzWhy.length)" ascii
    $s16 = "function IotHCRP(dTYrejuX,PFlKEbTfdzz) {var MhMWtoXlsD=[wRhUYZjzzSMZuvBmkqrmi[15]];dTYrejuX[MhMWtoXlsD[0]]" fullword ascii
    $s17 = "function fDdRVyKPWzjU(){return eIqSxMmttJV(wRhUYZjzzSMZuvBmkqrmi[13],[0,3,6],wRhUYZjzzSMZuvBmkqrmi[14]);}" fullword ascii
    $s18 = "function QFtzTcoWGeUe(){return eIqSxMmttJV(wRhUYZjzzSMZuvBmkqrmi[9],[1,5,7],wRhUYZjzzSMZuvBmkqrmi[10]);}" fullword ascii
    $s19 = "function UwrUFSwmXUwYmkKVQxGhQY(EKbrfIWjgrEIdCzRRFxEgY,dvtVNB,rZIao){return String.fromCharCode(EKbrfIWjgrEIdCzRRFxEgY,dvtVNB,rZ" ascii
    $s20 = "rCsKclJsRQUopo = glHoLeEELqbeakMyacK & 0xff;if (IAXKKFrGjDjQlcNdPNZ == 64) ZssduvArYVQrxAXDuNI += kg(ebQBtHOnKZ);else if (JseWld" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}