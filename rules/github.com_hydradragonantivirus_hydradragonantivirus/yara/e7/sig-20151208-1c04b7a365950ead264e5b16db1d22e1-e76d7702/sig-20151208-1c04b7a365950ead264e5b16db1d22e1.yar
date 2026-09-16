rule sig_20151208_1c04b7a365950ead264e5b16db1d22e1 {
  meta:
    description = "datamaliciousorder - file 20151208_1c04b7a365950ead264e5b16db1d22e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed358785c1693ac408af1f376ee12738b272351576ad481cbcd82be1dc563352"

  strings:
    $s1  = "function fteLiLB(iAkCGfyrkciByBCSynnDsXtMZSqBOgtHcClv) {return !isNaN(parseFloat(iAkCGfyrkciByBCSynnDsXtMZSqBOgtHcClv)) && isFin" ascii
    $s2  = "function fteLiLB(iAkCGfyrkciByBCSynnDsXtMZSqBOgtHcClv) {return !isNaN(parseFloat(iAkCGfyrkciByBCSynnDsXtMZSqBOgtHcClv)) && isFin" ascii
    $s3  = "function jIoaTumzNtFTpxETW(ikMko){UFAyiDsLWDb= '';for(vsRcaYwfPnW=(-132+132)/715; vsRcaYwfPnW < (529+525)/527; vsRcaYwfPnW++) {I" ascii
    $s4  = "function jIoaTumzNtFTpxETW(ikMko){UFAyiDsLWDb= '';for(vsRcaYwfPnW=(-132+132)/715; vsRcaYwfPnW < (529+525)/527; vsRcaYwfPnW++) {I" ascii
    $s5  = "push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"87\");d.push(\"83\");d.push(\"99\");d.push(\"114\");d.push(\"105\");d.push(" ascii
    $s6  = ";return mpadT;}function uuIgbhHjNdMTeBg(aqFVFpkSDAyrmEwYa){eval(aqFVFpkSDAyrmEwYa)}" fullword ascii
    $s7  = "}} return UFAyiDsLWDb}" fullword ascii
    $s8  = "push(\"44\");Z.push(\"34\");Z.push(\"104\");Z.push(\"116\");Z.push(\"116\");Z.push(\"112\");Z.push(\"58\");Z.push(\"47\");Z.push" ascii
    $s9  = "function UOxflZNqGAOrkNVDXSixjoJFnIMDVPemtXZiIWIkWkzglywNBLPnwe(hwFxknnjNmrRX,ZRJKIeIaZlfPVa){ return VFHTSuuTGcwpq[EMGiA(hwFxkn" ascii
    $s10 = "function jWEDJzygFgN(SDIVJdwY,OELnNC){return SDIVJdwY.split(OELnNC)}" fullword ascii
    $s11 = "dgpJV)}function EMGiA(EOGpqzkQreh,oGiPdIQMYeaYB,hFRkUldz){DRIF=parseInt(EOGpqzkQreh,oGiPdIQMYeaYB);mpadT=DRIF.toString(hFRkUldz)" ascii
    $s12 = "function UOxflZNqGAOrkNVDXSixjoJFnIMDVPemtXZiIWIkWkzglywNBLPnwe(hwFxknnjNmrRX,ZRJKIeIaZlfPVa){ return VFHTSuuTGcwpq[EMGiA(hwFxkn" ascii
    $s13 = "push(\"50\");Z.push(\"51\");Z.push(\"57\");Z.push(\"49\");Z.push(\"45\");Z.push(\"52\");Z.push(\"56\");Z.push(\"53\");Z.push(\"4" ascii
    $s14 = "push(\"32\");Z.push(\"32\");Z.push(\"125\");Z.push(\"59\");Z.push(\"32\");Z.push(\"76\");Z.push(\"75\");Z.push(\"110\");Z.push(" ascii
    $s15 = "var VFHTSuuTGcwpq=[];for(sRdgpJV=(-534+534)/596;sRdgpJV<(41182+802)/328;sRdgpJV++){VFHTSuuTGcwpq[sRdgpJV]=String.fromCharCode(sR" ascii
    $s16 = "push(\"10\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"76\");Z.push(\"7" ascii
    $s17 = "push(\"87\");d.push(\"83\");d.push(\"99\");d.push(\"114\");d.push(\"105\");d.push(\"34\");d.push(\"58\");d.push(\"34\");d.push(" ascii
    $s18 = "push(\"47\");d.push(\"42\");d.push(\"78\");d.push(\"69\");d.push(\"50\");d.push(\"104\");d.push(\"57\");d.push(\"54\");d.push(\"" ascii
    $s19 = "push(\"9\");Z.push(\"105\");Z.push(\"102\");Z.push(\"32\");Z.push(\"40\");Z.push(\"69\");Z.push(\"102\");Z.push(\"32\");Z.push(" ascii
    $s20 = "push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"34\");d.push(\"37\");d.push(\"84\");d.push(\"69\");d.push(\"77\");d.push(\"8" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}