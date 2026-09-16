rule sig_20151209_dbbb4ddd142fb3c6d7b32d51b0067732 {
  meta:
    description = "datamaliciousorder - file 20151209_dbbb4ddd142fb3c6d7b32d51b0067732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2b6df834bd2c17e552db85f8ad8a89609cf769e56497123ec4168d408f5ddc3"

  strings:
    $s1  = "function cEyKrUnkUxtfYWvFZ(XTiOb){KqDmtGXeJMc= '';for(vBzDneSaevv=(-91+91)/503; vBzDneSaevv < (1279+473)/876; vBzDneSaevv++) {Zh" ascii
    $s2  = "function kCmkWoT(UsKwvicCWTgRdagtayVCDLEouiqyjRiOhscn) {return !isNaN(parseFloat(UsKwvicCWTgRdagtayVCDLEouiqyjRiOhscn)) && isFin" ascii
    $s3  = "function CtjovggxkaMCnTXcpTOpPAVVvhCBdnaDFGMTgakercRIljhCuRlbIn(KklKhFbmarTuv,ekMSbQBoUFvjpp){ return aAtgT[LnJAy(KklKhFbmarTuv[" ascii
    $s4  = "function kCmkWoT(UsKwvicCWTgRdagtayVCDLEouiqyjRiOhscn) {return !isNaN(parseFloat(UsKwvicCWTgRdagtayVCDLEouiqyjRiOhscn)) && isFin" ascii
    $s5  = "function CtjovggxkaMCnTXcpTOpPAVVvhCBdnaDFGMTgakercRIljhCuRlbIn(KklKhFbmarTuv,ekMSbQBoUFvjpp){ return aAtgT[LnJAy(KklKhFbmarTuv[" ascii
    $s6  = "function cEyKrUnkUxtfYWvFZ(XTiOb){KqDmtGXeJMc= '';for(vBzDneSaevv=(-91+91)/503; vBzDneSaevv < (1279+473)/876; vBzDneSaevv++) {Zh" ascii
    $s7  = "lhCRacc[vBzDneSaevv]=(-16+16)/479; while(true) { if(ZhlhCRacc[vBzDneSaevv] > XTiOb[vBzDneSaevv].length-(-49+982)/933) { break; }" ascii
    $s8  = " GTzNb;}function NpcSOsEKNYkdUmT(tBfunhiCMaNgvTrFd){eval(tBfunhiCMaNgvTrFd)}" fullword ascii
    $s9  = "function LnJAy(mCqaMwmqgDk,FfzsHzxgjMuVT,gfTRNVVR){elbD=parseInt(mCqaMwmqgDk,FfzsHzxgjMuVT);GTzNb=elbD.toString(gfTRNVVR);return" ascii
    $s10 = "function kirjVgaSUog(iPhRsXLw,XMKgBr){return iPhRsXLw.split(XMKgBr)}" fullword ascii
    $s11 = "function LnJAy(mCqaMwmqgDk,FfzsHzxgjMuVT,gfTRNVVR){elbD=parseInt(mCqaMwmqgDk,FfzsHzxgjMuVT);GTzNb=elbD.toString(gfTRNVVR);return" ascii
    $s12 = "} return KqDmtGXeJMc}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}