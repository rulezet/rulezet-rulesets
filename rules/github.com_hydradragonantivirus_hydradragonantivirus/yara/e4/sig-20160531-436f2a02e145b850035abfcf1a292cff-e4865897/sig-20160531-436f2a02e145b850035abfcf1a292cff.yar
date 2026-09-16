rule sig_20160531_436f2a02e145b850035abfcf1a292cff {
  meta:
    description = "datamaliciousorder - file 20160531_436f2a02e145b850035abfcf1a292cff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73726ebb05788d0b381a66cc6cdbb05ee067205d356894a4ea0444072c5ac9ba"

  strings:
    $s1  = "var LsuJUAauktU=function(){return WScript.CreateObject(ISVOGtlmuq[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function JjgrZEdKzkNpI(bMzErjioHobcJf,jYNJODmDIWQo){return bMzErjioHobcJf.charAt(jYNJODmDIWQo);}" fullword ascii
    $s3  = "function ZgNZqpIlvk(jrLRVdTgtAlUK,EHVhmWZ,aoLtprEybvLj){IchvlqMSnRO=jrLRVdTgtAlUK.split(aoLtprEybvLj);cZftxv = ISVOGtlmuq[0];for" ascii
    $s4  = "function ZI(fgFKtZGFJWhxLpbotZOyn){return String.fromCharCode(fgFKtZGFJWhxLpbotZOyn);}" fullword ascii
    $s5  = "sKzmSu, cfGcykhxSviUSR);} while (cfNtRDYglVbRydIoK < dHRpfUOkDppds.length);return dvkqAhNwMPJVMhRpNO;}" fullword ascii
    $s6  = "function wvtUlq(){return LsuJUAauktU.ExpandEnvironmentStrings(RBusTDJ())}" fullword ascii
    $s7  = "(MgPunaULqD,0x1,0x0)}function hzAFcLAJQfQ(YrkKf,UQqNJAsUwQfWjg,rCCWesFS){var mkphU=YrkKf.createtextfile(UQqNJAsUwQfWjg,true);mkp" ascii
    $s8  = "function RBusTDJ(){return ZgNZqpIlvk(ISVOGtlmuq[9],[1,5,7],ISVOGtlmuq[10]);}" fullword ascii
    $s9  = "function woCSog(){return ZgNZqpIlvk(ISVOGtlmuq[11],[2,4,8,10],ISVOGtlmuq[12]);}" fullword ascii
    $s10 = "var tqdMGztRh=function(){return new ActiveXObject(ISVOGtlmuq[1]);}();" fullword ascii
    $s11 = "function nojCknXFiFM(dHRpfUOkDppds) {var IJVDprAKDcmlwIkmbXpPuZkh = FVAIoMDpKQiHIajmO.join(ISVOGtlmuq[7]);var CLgxfckxvMzN, oeXh" ascii
    $s12 = "function ZOqxMKERfE(DTigFQXktdmJRQYnqW,qEHiwr){return String.fromCharCode(DTigFQXktdmJRQYnqW,qEHiwr);}" fullword ascii
    $s13 = "function llazMADoR(hkbWotLm,MgPunaULqD) {var SEhUwQBYXr=[ISVOGtlmuq[15]];hkbWotLm[SEhUwQBYXr[0]]" fullword ascii
    $s14 = "(gVVNFhBcErOz=0;gVVNFhBcErOz<EHVhmWZ.length;gVVNFhBcErOz++) {cZftxv+=IchvlqMSnRO[EHVhmWZ[gVVNFhBcErOz]];}return cZftxv.substring" ascii
    $s15 = "function ajxPSVvWC(bLhMFdULusiDszRYRm,uryjeUHlL,MBBAKwpbiMETMqJhoZv){return String.fromCharCode(bLhMFdULusiDszRYRm,uryjeUHlL,MBB" ascii
    $s16 = "kqAhNwMPJVMhRpNO += ZOqxMKERfE(CLgxfckxvMzN, oeXhZcRqqCNmsKzmSu);else dvkqAhNwMPJVMhRpNO += ajxPSVvWC(CLgxfckxvMzN, oeXhZcRqqCNm" ascii
    $s17 = "function ajxPSVvWC(bLhMFdULusiDszRYRm,uryjeUHlL,MBBAKwpbiMETMqJhoZv){return String.fromCharCode(bLhMFdULusiDszRYRm,uryjeUHlL,MBB" ascii
    $s18 = "function ZgNZqpIlvk(jrLRVdTgtAlUK,EHVhmWZ,aoLtprEybvLj){IchvlqMSnRO=jrLRVdTgtAlUK.split(aoLtprEybvLj);cZftxv = ISVOGtlmuq[0];for" ascii
    $s19 = "(MgPunaULqD,0x1,0x0)}function hzAFcLAJQfQ(YrkKf,UQqNJAsUwQfWjg,rCCWesFS){var mkphU=YrkKf.createtextfile(UQqNJAsUwQfWjg,true);mkp" ascii
    $s20 = "0xff;cfGcykhxSviUSR = IGmNsAP & 0xff;if (awYBglDhDdnGH == 64) dvkqAhNwMPJVMhRpNO += ZI(CLgxfckxvMzN);else if (CEXyssFL == 64) dv" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}