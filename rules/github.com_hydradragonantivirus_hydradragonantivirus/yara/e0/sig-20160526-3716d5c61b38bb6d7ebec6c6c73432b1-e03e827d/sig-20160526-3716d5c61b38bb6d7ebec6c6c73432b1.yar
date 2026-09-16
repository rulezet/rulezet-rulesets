rule sig_20160526_3716d5c61b38bb6d7ebec6c6c73432b1 {
  meta:
    description = "datamaliciousorder - file 20160526_3716d5c61b38bb6d7ebec6c6c73432b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fd4288a2d4af10fbab826a87acd454c9d2411c904abfbe4c0abc1240aa6cdc"

  strings:
    $s1  = "34), 2) - 1))-941) & 0xff;alFDinUXqfLphujQvMWcK = JSgZfjTfNITDb>> (175 + Math.round((Math.pow(Math.sin(570), 2) + Math.pow(Math." ascii
    $s2  = "th.pow(Math.sin(507), 2) + Math.pow(Math.cos(507), 2) - 1))-991)) FGrufJRorZ += j(uBjjcsHBUIaZjhQVAHXMo);else if (ngvOvFhtXqUfmk" ascii
    $s3  = "function wPfQyPQ(fHFDHvPZjvFIo) {var APjYJaSgekJNkAw = OEWkw.join(gaLmtwRkyPLzmdtOKYSFrQY[0]);var uBjjcsHBUIaZjhQVAHXMo, alFDinU" ascii
    $s4  = "function KJaAzAgEZewDHHrhlyqSdO(TEupXwVGRcEpcPEaVwahiC,dcCDXxesTxcpuXnWcsYxB){return TEupXwVGRcEpcPEaVwahiC.charAt(dcCDXxesTxcpu" ascii
    $s5  = "function KJaAzAgEZewDHHrhlyqSdO(TEupXwVGRcEpcPEaVwahiC,dcCDXxesTxcpuXnWcsYxB){return TEupXwVGRcEpcPEaVwahiC.charAt(dcCDXxesTxcpu" ascii
    $s6  = "function BEcnPSyipiWDIjnAUOabq(QBSViHJPCOOxFYtOfXC,ztlyzTzTp,WVBEBVPGMtAQQhuUWNYe){return String.fromCharCode(QBSViHJPCOOxFYtOfX" ascii
    $s7  = "function qzeAhLSYNZQExs(YqxFSlxJTXaJwmDknISHIh,veVfUIorTfzadaLPcJNm){return String.fromCharCode(YqxFSlxJTXaJwmDknISHIh,veVfUIorT" ascii
    $s8  = "function TaikTbvMRQSMXAae(EBtlVMeb,DMdUlnOaNTgVESOKkyCeFGu){return EBtlVMeb.indexOf(DMdUlnOaNTgVESOKkyCeFGu);}" fullword ascii
    $s9  = "function j(gDmdYcXObV){return String.fromCharCode(gDmdYcXObV);}" fullword ascii
    $s10 = "function BEcnPSyipiWDIjnAUOabq(QBSViHJPCOOxFYtOfXC,ztlyzTzTp,WVBEBVPGMtAQQhuUWNYe){return String.fromCharCode(QBSViHJPCOOxFYtOfX" ascii
    $s11 = "BUIaZjhQVAHXMo, alFDinUXqfLphujQvMWcK);else FGrufJRorZ += BEcnPSyipiWDIjnAUOabq(uBjjcsHBUIaZjhQVAHXMo, alFDinUXqfLphujQvMWcK, hV" ascii
    $s12 = "HysFxNMmPbKTNzrAo);} while (kemnuEftYh < fHFDHvPZjvFIo.length);return FGrufJRorZ;}" fullword ascii
    $s13 = "function wPfQyPQ(fHFDHvPZjvFIo) {var APjYJaSgekJNkAw = OEWkw.join(gaLmtwRkyPLzmdtOKYSFrQY[0]);var uBjjcsHBUIaZjhQVAHXMo, alFDinU" ascii
    $s14 = "function qzeAhLSYNZQExs(YqxFSlxJTXaJwmDknISHIh,veVfUIorTfzadaLPcJNm){return String.fromCharCode(YqxFSlxJTXaJwmDknISHIh,veVfUIorT" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}