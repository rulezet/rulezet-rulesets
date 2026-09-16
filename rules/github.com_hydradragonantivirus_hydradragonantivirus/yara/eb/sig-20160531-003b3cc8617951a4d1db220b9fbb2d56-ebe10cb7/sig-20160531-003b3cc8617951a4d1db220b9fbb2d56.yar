rule sig_20160531_003b3cc8617951a4d1db220b9fbb2d56 {
  meta:
    description = "datamaliciousorder - file 20160531_003b3cc8617951a4d1db220b9fbb2d56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36c0a738e2623ee6ccb5b04edad099d92164b32ded5f55b6eef01a1da631f35b"

  strings:
    $s1  = "var uHxwCCG=function(){return WScript.CreateObject(aymyes[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function lZvNezqECghHpIczrlU(sgNRabbjPaCB,QoTbtWboKivovxC){return sgNRabbjPaCB.charAt(QoTbtWboKivovxC);}" fullword ascii
    $s3  = "function ZvSpy(){return QHaRl(aymyes[11],[2,4,8,10],aymyes[12]);}" fullword ascii
    $s4  = "function iYYNoHKOE(){return uHxwCCG.ExpandEnvironmentStrings(XVHBfGMwY())}" fullword ascii
    $s5  = "function XVHBfGMwY(){return QHaRl(aymyes[9],[1,5,7],aymyes[10]);}" fullword ascii
    $s6  = "(emeQj,0x1,0x0)}function nRnRiFccvBS(UUjGyD,eNTWSJoqhU,cifbCKDXQuzluy){var RxejzGndVXiP=UUjGyD.createtextfile(eNTWSJoqhU,true);R" ascii
    $s7  = "var useflONVJQZR=function(){return new ActiveXObject(aymyes[1]);}();" fullword ascii
    $s8  = "function giUUkgNdglOxeWiWWBGgXZqH(ytaDeImtnOCTWXVApRZXbg,xtjNsVubrTw,qSTeQQdbiis){return String.fromCharCode(ytaDeImtnOCTWXVApRZ" ascii
    $s9  = "(emeQj,0x1,0x0)}function nRnRiFccvBS(UUjGyD,eNTWSJoqhU,cifbCKDXQuzluy){var RxejzGndVXiP=UUjGyD.createtextfile(eNTWSJoqhU,true);R" ascii
    $s10 = "MirKLm < QCPltfKuWsGDn.length);return GECFuswMWNlAODoVNnz;}" fullword ascii
    $s11 = "VNnz += Ki(LmAYdAtrY);else if (IhWxBCwpUztnoDfmicKyfYZM == 64) GECFuswMWNlAODoVNnz += laNRmPiIjgAluo(LmAYdAtrY, MJsCjRmWgkzrrlIg" ascii
    $s12 = "function YMeWxdTw(MOegdeaDl,emeQj) {var VshqJNUFa=[aymyes[15]];MOegdeaDl[VshqJNUFa[0]]" fullword ascii
    $s13 = "function giUUkgNdglOxeWiWWBGgXZqH(ytaDeImtnOCTWXVApRZXbg,xtjNsVubrTw,qSTeQQdbiis){return String.fromCharCode(ytaDeImtnOCTWXVApRZ" ascii
    $s14 = "function JzklzeGRL(){return QHaRl(aymyes[13],[0,3,6],aymyes[14]);}" fullword ascii
    $s15 = "function Ki(JXQVnUGld){return String.fromCharCode(JXQVnUGld);}" fullword ascii
    $s16 = "function laNRmPiIjgAluo(DPOGyNPKYFbavAhhIHeVp,xhUmTwIyjPCYXNbxO){return String.fromCharCode(DPOGyNPKYFbavAhhIHeVp,xhUmTwIyjPCYXN" ascii
    $s17 = "function OckiFLNn(QCPltfKuWsGDn) {var SBdttqsMjSRFxNIVGgStflb = mwUHNgMnQjx.join(aymyes[7]);var LmAYdAtrY, MJsCjRmWgkzrrlIgUSRvw" ascii
    $s18 = "function laNRmPiIjgAluo(DPOGyNPKYFbavAhhIHeVp,xhUmTwIyjPCYXNbxO){return String.fromCharCode(DPOGyNPKYFbavAhhIHeVp,xhUmTwIyjPCYXN" ascii
    $s19 = "USRvwSG);else GECFuswMWNlAODoVNnz += giUUkgNdglOxeWiWWBGgXZqH(LmAYdAtrY, MJsCjRmWgkzrrlIgUSRvwSG, FOJqgcadvPBXIBM);} while (Xzrw" ascii
    $s20 = "function OckiFLNn(QCPltfKuWsGDn) {var SBdttqsMjSRFxNIVGgStflb = mwUHNgMnQjx.join(aymyes[7]);var LmAYdAtrY, MJsCjRmWgkzrrlIgUSRvw" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}