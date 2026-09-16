rule sig_20160526_7c23aabd5b63a0012529ee2a09183b92 {
  meta:
    description = "datamaliciousorder - file 20160526_7c23aabd5b63a0012529ee2a09183b92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85498ff8f6238d82ac0e982648617e860927e3a1766b52120d091b54f36fa6e9"

  strings:
    $s1  = "yutbmWcipbwYtZzq);else if (CCGRpTbZJSWDZSOXZ == (139 + Math.round((Math.pow(Math.sin(61), 2) + Math.pow(Math.cos(61), 2) - 1))-7" ascii
    $s2  = "function vrriCnWBldEIc(faTHAFqzNrysW) {var iIelmTqPWQeopr = iYQBAtu.join(sLJZAWdolwQ[0]);var CkbMhHPyutbmWcipbwYtZzq, sDgjaVbxJl" ascii
    $s3  = "function kjbHlGbFDjPbhRMVg(mBwwCtLp,DGXvpsC){return mBwwCtLp.charAt(DGXvpsC);}" fullword ascii
    $s4  = "function FviTfUA(fxgxFDlBK,qoHGdAvNLkcJ,oCJwKoaBBhiVeowKt){return String.fromCharCode(fxgxFDlBK,qoHGdAvNLkcJ,oCJwKoaBBhiVeowKt);" ascii
    $s5  = "hHPyutbmWcipbwYtZzq, sDgjaVbxJlHNuCv, FEYPfwi);} while (vGpkgQADMwWYDOUUPXMdh < faTHAFqzNrysW.length);return qgIqVelhlQpAzTQIcgJ" ascii
    $s6  = "function G(ypCfsbvhQkeZqoLUREajPtq){return String.fromCharCode(ypCfsbvhQkeZqoLUREajPtq);}" fullword ascii
    $s7  = "function gPFqzOkL(bMFpokmFyOwgENq,mNckvrCng){return String.fromCharCode(bMFpokmFyOwgENq,mNckvrCng);}" fullword ascii
    $s8  = "function tubUbRsTufhQXOz(akLirwnZ,QjHVayZCuSNYTBtkROyIBlFv){return akLirwnZ.indexOf(QjHVayZCuSNYTBtkROyIBlFv);}" fullword ascii
    $s9  = "function vrriCnWBldEIc(faTHAFqzNrysW) {var iIelmTqPWQeopr = iYQBAtu.join(sLJZAWdolwQ[0]);var CkbMhHPyutbmWcipbwYtZzq, sDgjaVbxJl" ascii
    $s10 = "5)) qgIqVelhlQpAzTQIcgJXJdzC += gPFqzOkL(CkbMhHPyutbmWcipbwYtZzq, sDgjaVbxJlHNuCv);else qgIqVelhlQpAzTQIcgJXJdzC += FviTfUA(CkbM" ascii
    $s11 = "function FviTfUA(fxgxFDlBK,qoHGdAvNLkcJ,oCJwKoaBBhiVeowKt){return String.fromCharCode(fxgxFDlBK,qoHGdAvNLkcJ,oCJwKoaBBhiVeowKt);" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}