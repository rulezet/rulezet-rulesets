rule sig_20151217_5d2baf3c275f28c2b4a578d699d6bfc5 {
  meta:
    description = "datamaliciousorder - file 20151217_5d2baf3c275f28c2b4a578d699d6bfc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69f7788d223836db4c001e607a45c167f53556b8bfd08313a17feb61c9c0a8a"

  strings:
    $s1  = "Math.cos(179), 2) - 1)));} xHElKCjnV[EAbYlphsCGx]++;}EAbYlphsCGx++;} return viAfvpJquQW}" fullword ascii
    $s2  = ") - 1));while(true){if (EAbYlphsCGx >= (1293+963)/376){break;}xHElKCjnV[EAbYlphsCGx]=Math.round((Math.pow(Math.sin(24), 2) + Mat" ascii
    $s3  = "function JxqlsNLNvhmnguaUT(TQfpv){viAfvpJquQW= '';EAbYlphsCGx=Math.round((Math.pow(Math.sin(923), 2) + Math.pow(Math.cos(923), 2" ascii
    $s4  = "h.pow(Math.cos(24), 2) - 1)); while(true) { if(xHElKCjnV[EAbYlphsCGx] > TQfpv[EAbYlphsCGx].length-(80+92)/172) { break; } if (FU" ascii
    $s5  = "function JxqlsNLNvhmnguaUT(TQfpv){viAfvpJquQW= '';EAbYlphsCGx=Math.round((Math.pow(Math.sin(923), 2) + Math.pow(Math.cos(923), 2" ascii
    $s6  = "function YXlYsvplMeOkJHuzHELWOPOKgfTTSIuFmofUoFFViYqGmfrGUVktTc(UryIAtTtMpzsx,cJEOhzVMyTyNVt){ return jYOceDq[xkalqKZz[DXhie(Ury" ascii
    $s7  = "function FUdSRdF(RKGdNApVuWEXUtqiDDaYKMdcYIwLkblafOSt) {return !dDihzoDGIuA(VGbgVwzRgZUuqIa(RKGdNApVuWEXUtqiDDaYKMdcYIwLkblafOSt" ascii
    $s8  = "function YXlYsvplMeOkJHuzHELWOPOKgfTTSIuFmofUoFFViYqGmfrGUVktTc(UryIAtTtMpzsx,cJEOhzVMyTyNVt){ return jYOceDq[xkalqKZz[DXhie(Ury" ascii
    $s9  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s10 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s11 = "function yXUPkPrdaBdi(sNuYUwBASNwpt) {return isFinite(sNuYUwBASNwpt);}" fullword ascii
    $s12 = "function DXhie(iMLMIbflhMi,AgLYfuwJifJQk,pAQWIPYE){dzdf=vsnFNwkGtBQHvLNbQ(iMLMIbflhMi,AgLYfuwJifJQk);oohjY=dzdf.toString(pAQWIPY" ascii
    $s13 = "function g(UQlrScgACycB,NUxnhstDLmfArh){UQlrScgACycB.push(NUxnhstDLmfArh);}" fullword ascii
    $s14 = "function VGbgVwzRgZUuqIa(hhDqHQeZCHLIFIyZhKq) {return parseFloat(hhDqHQeZCHLIFIyZhKq);}" fullword ascii
    $s15 = "function FUdSRdF(RKGdNApVuWEXUtqiDDaYKMdcYIwLkblafOSt) {return !dDihzoDGIuA(VGbgVwzRgZUuqIa(RKGdNApVuWEXUtqiDDaYKMdcYIwLkblafOSt" ascii
    $s16 = "function vNiheRhTKjEtsgC(ysuoyAHdbgqEpYcwb,UIHfOPsTQHsRaqrBZjqhZypbbjQHKcCQBc,nJqcKmOhkGIAAKIOCGuUzdRPqKdSBUfbwCl){eval(ysuoyAHd" ascii
    $s17 = "function DXhie(iMLMIbflhMi,AgLYfuwJifJQk,pAQWIPYE){dzdf=vsnFNwkGtBQHvLNbQ(iMLMIbflhMi,AgLYfuwJifJQk);oohjY=dzdf.toString(pAQWIPY" ascii
    $s18 = "function vNiheRhTKjEtsgC(ysuoyAHdbgqEpYcwb,UIHfOPsTQHsRaqrBZjqhZypbbjQHKcCQBc,nJqcKmOhkGIAAKIOCGuUzdRPqKdSBUfbwCl){eval(ysuoyAHd" ascii
    $s19 = "function dDihzoDGIuA(XBdOyFgzGbZxjl) {return isNaN(XBdOyFgzGbZxjl);}" fullword ascii
    $s20 = "function vsnFNwkGtBQHvLNbQ(LEWRJooxLy,FRzcxbArAe) {return parseInt(LEWRJooxLy,FRzcxbArAe);}" fullword ascii

  condition:
    uint16(0) == 0x6b78 and
    8 of them
}