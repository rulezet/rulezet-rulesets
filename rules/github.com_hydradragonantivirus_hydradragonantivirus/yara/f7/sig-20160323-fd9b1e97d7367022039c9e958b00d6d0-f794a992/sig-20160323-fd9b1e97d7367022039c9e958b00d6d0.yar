rule sig_20160323_fd9b1e97d7367022039c9e958b00d6d0 {
  meta:
    description = "datamaliciousorder - file 20160323_fd9b1e97d7367022039c9e958b00d6d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12df092f71a74d303d18948bbc1597e1084f550f33b44c5ac5da5ad2c67ce15a"

  strings:
    $s1  = "return WScript.CreateObject(OCwog);" fullword ascii
    $s2  = "return wvvgEMz[0] + wvvgEMz[2] + wvvgEMz[4] + \".F\" + wvvgEMz[7] + wvvgEMz[9] + wvvgEMz[12] + wvvgEMz[14];" fullword ascii
    $s3  = "var Yr = true  , UrPt = Svz[7] + Svz[9] + Svz[11];" fullword ascii
    $s4  = "var Svz = (\"2.XMLHTTP XVFugTw VRgUF XML ream St foGDpKEC AD SFajfDa O wSZs D\").split(\" \");" fullword ascii
    $s5  = "mQnJ.open(wTqwh,MQlmx,false);" fullword ascii
    $s6  = "if(T>=c.length) {break;}" fullword ascii
    $s7  = "function iUIvt(mJPULh) {" fullword ascii
    $s8  = "if (qmvDX == 366-166){return true;} else {return false;}" fullword ascii
    $s9  = "if (K >= Adwwb.length) {break;}" fullword ascii
    $s10 = "return JXJJ[bzLrEl[0]];" fullword ascii
    $s11 = "return MbI.size;" fullword ascii
    $s12 = "return rfgau.status;" fullword ascii
    $s13 = "function xKds(Adwwb) {" fullword ascii
    $s14 = "function uRji(wOqdg,MQlmx,wTqwh) {" fullword ascii
    $s15 = "return new ActiveXObject(IIQb);" fullword ascii
    $s16 = "return jurQSmn(uu,xAGsJ[393-387]+xAGsJ[741-734]+xAGsJ[536-528]);" fullword ascii
    $s17 = "function UBeq(qmvDX) {" fullword ascii
    $s18 = "function jnVm(dUnSz) {" fullword ascii
    $s19 = "function jihm(OkIqo,XMOxD) {" fullword ascii
    $s20 = "function qNdLdKLyw(Aodxf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}