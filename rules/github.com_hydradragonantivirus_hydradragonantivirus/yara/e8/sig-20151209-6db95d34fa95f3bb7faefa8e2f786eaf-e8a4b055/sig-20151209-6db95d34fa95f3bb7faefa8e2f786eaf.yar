rule sig_20151209_6db95d34fa95f3bb7faefa8e2f786eaf {
  meta:
    description = "datamaliciousorder - file 20151209_6db95d34fa95f3bb7faefa8e2f786eaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07d0c0c884dd8200e31f2692d8c16ef84931cbeb0748c8bcd2033251fa18133d"

  strings:
    $s1  = "rUlwtkbY[FChUEhXgPkB]=(-678+678)/904; while(true) { if(wrUlwtkbY[FChUEhXgPkB] > cTzvL[FChUEhXgPkB].length-(230+437)/667) { break" ascii
    $s2  = "+;}} return tjKOQcTNdyp}" fullword ascii
    $s3  = "function RkjwTvglhnT(GlIOlldG,HIOyVJ){return GlIOlldG.split(HIOyVJ)}" fullword ascii
    $s4  = "function opDWEdhAdKpHxzVwp(cTzvL){tjKOQcTNdyp= '';for(FChUEhXgPkB=(-790+790)/215; FChUEhXgPkB < (-479+501)/11; FChUEhXgPkB++) {w" ascii
    $s5  = "function CvjIV(zKTnyaWUjPJ,aJZdrVTXIBLZG,tyFzSTDh){MKvK=parseInt(zKTnyaWUjPJ,aJZdrVTXIBLZG);SYALJ=MKvK.toString(tyFzSTDh);return" ascii
    $s6  = "function yfULyWHayzLcLGBIvKguxTupODekRwCkXJhKvOdTRkZLcHDufSdZLw(sBAVkFWfwbcDn,eBJWSXombeuuna){ return WkJZG[CvjIV(sBAVkFWfwbcDn[" ascii
    $s7  = "function yfULyWHayzLcLGBIvKguxTupODekRwCkXJhKvOdTRkZLcHDufSdZLw(sBAVkFWfwbcDn,eBJWSXombeuuna){ return WkJZG[CvjIV(sBAVkFWfwbcDn[" ascii
    $s8  = " SYALJ;}function sCeSTRKrzjvpvBY(qIzUvfyRztJuKGSOs){eval(qIzUvfyRztJuKGSOs)}" fullword ascii
    $s9  = "function CvjIV(zKTnyaWUjPJ,aJZdrVTXIBLZG,tyFzSTDh){MKvK=parseInt(zKTnyaWUjPJ,aJZdrVTXIBLZG);SYALJ=MKvK.toString(tyFzSTDh);return" ascii
    $s10 = "function opDWEdhAdKpHxzVwp(cTzvL){tjKOQcTNdyp= '';for(FChUEhXgPkB=(-790+790)/215; FChUEhXgPkB < (-479+501)/11; FChUEhXgPkB++) {w" ascii
    $s11 = "function VBFmhSZ(QrhiDBvAXCmETELMSrjwJgNNlsOaMbQCAIBZ) {return !isNaN(parseFloat(QrhiDBvAXCmETELMSrjwJgNNlsOaMbQCAIBZ)) && isFin" ascii
    $s12 = "function VBFmhSZ(QrhiDBvAXCmETELMSrjwJgNNlsOaMbQCAIBZ) {return !isNaN(parseFloat(QrhiDBvAXCmETELMSrjwJgNNlsOaMbQCAIBZ)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}