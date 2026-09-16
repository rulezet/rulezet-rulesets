rule sig_20160526_bdd26fab3cfd378b07d1ed4276b72b9e {
  meta:
    description = "datamaliciousorder - file 20160526_bdd26fab3cfd378b07d1ed4276b72b9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7992c6f2d6acaf3584fa4c89fd3ba46a72b7406c6ed5b7b2851274011585495"

  strings:
    $s1  = "function QSNSR(MtsoohEvLaKCs) {var VtdTQNDreaWqHLyDMAFCu = JUmRsfmuzhFqJcNt.join(RIXQsstr[0]);var TnJIDrTntTstchNzaWMRen, YdEWrf" ascii
    $s2  = ";else if (ZkhwNgChrZMCDMzArULNItXu == (558 + Math.round((Math.pow(Math.sin(980), 2) + Math.pow(Math.cos(980), 2) - 1))-494)) iuU" ascii
    $s3  = "round((Math.pow(Math.sin(441), 2) + Math.pow(Math.cos(441), 2) - 1))-505) | UZGpFYvgmJpDyruIz<< (778 + Math.round((Math.pow(Math" ascii
    $s4  = "function sFXLElyvgxVrLtf(UnnEmjGLRtfBeLOOxCNaICT,vHXDlQlIQzGsV){return UnnEmjGLRtfBeLOOxCNaICT.charAt(vHXDlQlIQzGsV);}" fullword ascii
    $s5  = " = UkUiZDmgVDFlxKFPLrhk(VtdTQNDreaWqHLyDMAFCu,sFXLElyvgxVrLtf(MtsoohEvLaKCs,EWoHGgIaoEh++));sjzWaznsM = IDLyDWasH<< (523 + Math." ascii
    $s6  = "function nspElOT(NxAKDXMwIdKNeJaLUBFVApFb,LJuPUTYheXdwkxGXOgsrH,ycUHqAVtBJft){return String.fromCharCode(NxAKDXMwIdKNeJaLUBFVApF" ascii
    $s7  = "function UkUiZDmgVDFlxKFPLrhk(IPLiEsEZ,DAZQMR){return IPLiEsEZ.indexOf(DAZQMR);}" fullword ascii
    $s8  = "function eYGJlnqpdkNiGvaWMGTklXn(IoNGuBJAklLVHBCHKcxx,YhBVTfBrgZwU){return String.fromCharCode(IoNGuBJAklLVHBCHKcxx,YhBVTfBrgZwU" ascii
    $s9  = "rTntTstchNzaWMRen, YdEWrfAjeKnJNHntuwFCUSa, KMDFFFOI);} while (EWoHGgIaoEh < MtsoohEvLaKCs.length);return iuUFUHZIjLzDJAbz;}" fullword ascii
    $s10 = "function QSNSR(MtsoohEvLaKCs) {var VtdTQNDreaWqHLyDMAFCu = JUmRsfmuzhFqJcNt.join(RIXQsstr[0]);var TnJIDrTntTstchNzaWMRen, YdEWrf" ascii
    $s11 = "function eYGJlnqpdkNiGvaWMGTklXn(IoNGuBJAklLVHBCHKcxx,YhBVTfBrgZwU){return String.fromCharCode(IoNGuBJAklLVHBCHKcxx,YhBVTfBrgZwU" ascii
    $s12 = "function nspElOT(NxAKDXMwIdKNeJaLUBFVApFb,LJuPUTYheXdwkxGXOgsrH,ycUHqAVtBJft){return String.fromCharCode(NxAKDXMwIdKNeJaLUBFVApF" ascii
    $s13 = "FUHZIjLzDJAbz += eYGJlnqpdkNiGvaWMGTklXn(TnJIDrTntTstchNzaWMRen, YdEWrfAjeKnJNHntuwFCUSa);else iuUFUHZIjLzDJAbz += nspElOT(TnJID" ascii
    $s14 = "function vP(fBMsqTOjqqmYDGDfRrhRmePi){return String.fromCharCode(fBMsqTOjqqmYDGDfRrhRmePi);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}