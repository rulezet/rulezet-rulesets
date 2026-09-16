rule sig_20151211_0c3292f00fb0702f1bc993e154cd05f0 {
  meta:
    description = "datamaliciousorder - file 20151211_0c3292f00fb0702f1bc993e154cd05f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5db660a3b9144af07bfc64730ea3a634b2cbb776772db8b30d06905cf480d264"

  strings:
    $s1  = "function wqgEckk(OVshMjoXXoZRgVOOpRKCVoYGKvLbpMOwIOnM) {return !isNaN(parseFloat(OVshMjoXXoZRgVOOpRKCVoYGKvLbpMOwIOnM)) && isFin" ascii
    $s2  = "function wqgEckk(OVshMjoXXoZRgVOOpRKCVoYGKvLbpMOwIOnM) {return !isNaN(parseFloat(OVshMjoXXoZRgVOOpRKCVoYGKvLbpMOwIOnM)) && isFin" ascii
    $s3  = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "var D=new Array(\"26\",\"2a\",\"2d\",\"28\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "var O=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"38\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function SZUZn(iuAwXHNHTGr,qkNzCcedTNnyB,BVPNBGoB){iOtL=parseInt(iuAwXHNHTGr,qkNzCcedTNnyB);Buwed=iOtL.toString(BVPNBGoB);return" ascii
    $s7  = "function NigsomfcPDrdqkJBM(hXyhY){wHOPjJEdcDp= '';XQfYCwiIiar=(-411+411)/60; while(true){if(XQfYCwiIiar >= (981+457)/719)break;n" ascii
    $s8  = "function wPiBXEunUWyifiWhjzritJgEsAnLCHkHVdrHnQdpDkkokjxoTJkmfF(IpMhIcqvzRuaY,jZHlpaMXwaCsDs){ return jKnlM[SZUZn(IpMhIcqvzRuaY[" ascii
    $s9  = " Buwed;}function qjrYHWdRLNLAaCw(yidfgFCmUymLUvdtP){eval(yidfgFCmUymLUvdtP)}" fullword ascii
    $s10 = "RXwQBaMe[XQfYCwiIiar]=(-903+903)/253; while(true) { if(nRXwQBaMe[XQfYCwiIiar] > hXyhY[XQfYCwiIiar].length-(-114+386)/272) { brea" ascii
    $s11 = "function SZUZn(iuAwXHNHTGr,qkNzCcedTNnyB,BVPNBGoB){iOtL=parseInt(iuAwXHNHTGr,qkNzCcedTNnyB);Buwed=iOtL.toString(BVPNBGoB);return" ascii
    $s12 = "var D=new Array(\"26\",\"2a\",\"2d\",\"28\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "function NigsomfcPDrdqkJBM(hXyhY){wHOPjJEdcDp= '';XQfYCwiIiar=(-411+411)/60; while(true){if(XQfYCwiIiar >= (981+457)/719)break;n" ascii
    $s14 = "]++;}XQfYCwiIiar++;} return wHOPjJEdcDp}" fullword ascii
    $s15 = "function RyPohnVguBM(VkGXBieZ,wvYlDt){return VkGXBieZ.split(wvYlDt)}" fullword ascii
    $s16 = "function wPiBXEunUWyifiWhjzritJgEsAnLCHkHVdrHnQdpDkkokjxoTJkmfF(IpMhIcqvzRuaY,jZHlpaMXwaCsDs){ return jKnlM[SZUZn(IpMhIcqvzRuaY[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}