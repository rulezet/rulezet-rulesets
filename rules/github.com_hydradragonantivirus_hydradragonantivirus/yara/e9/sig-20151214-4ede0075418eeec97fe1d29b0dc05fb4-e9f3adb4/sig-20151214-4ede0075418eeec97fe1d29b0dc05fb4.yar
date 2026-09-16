rule sig_20151214_4ede0075418eeec97fe1d29b0dc05fb4 {
  meta:
    description = "datamaliciousorder - file 20151214_4ede0075418eeec97fe1d29b0dc05fb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ed33accd92ece02dc31b27a9421a293527a280eadde5ba028e0e2b517839d23"

  strings:
    $s1  = "ath.pow(Math.cos(771), 2) - 1)); while(true) { if(EySZdNgly[CQtnAxCyJwf] > FVnLV[CQtnAxCyJwf].length-(481+39)/520) { break; } if" ascii
    $s2  = "ow(Math.cos(690), 2) - 1)));} EySZdNgly[CQtnAxCyJwf]++;}} return UIOZFrsezGr}" fullword ascii
    $s3  = "function NxhGIEBjltimmwZaB(FVnLV){UIOZFrsezGr= u[1785];for(CQtnAxCyJwf=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.co" ascii
    $s4  = "function NxhGIEBjltimmwZaB(FVnLV){UIOZFrsezGr= u[1785];for(CQtnAxCyJwf=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.co" ascii
    $s5  = "kbtP)) {return (String.fromCharCode(OdilZSjDOXqBkbtP) + String.fromCharCode((73080+680)/922));}}" fullword ascii
    $s6  = "function D(EmHvboMVNnNf,UjriZxfjolBldy){EmHvboMVNnNf.push(UjriZxfjolBldy);}function L4(OdilZSjDOXqBkbtP){if(FqBlDnu(OdilZSjDOXqB" ascii
    $s7  = "function FqBlDnu(QoydQfAvWycZvGcuUWaqqCQeVAlnxnhXzYxX) {return !isNaN(parseFloat(QoydQfAvWycZvGcuUWaqqCQeVAlnxnhXzYxX)) && isFin" ascii
    $s8  = "function FqBlDnu(QoydQfAvWycZvGcuUWaqqCQeVAlnxnhXzYxX) {return !isNaN(parseFloat(QoydQfAvWycZvGcuUWaqqCQeVAlnxnhXzYxX)) && isFin" ascii
    $s9  = "function vvSUh(TsILvMnHthY,ZeyozVIgzDjjM,AoMxorZj){hEqo=parseInt(TsILvMnHthY,ZeyozVIgzDjjM);VSPag=hEqo.toString(AoMxorZj);return" ascii
    $s10 = "function vvSUh(TsILvMnHthY,ZeyozVIgzDjjM,AoMxorZj){hEqo=parseInt(TsILvMnHthY,ZeyozVIgzDjjM);VSPag=hEqo.toString(AoMxorZj);return" ascii
    $s11 = " VSPag;}function DahUBaPuxBIVwYL(OdLiQCNdSZWWhTBzT,NjJwhLzMEUJNVSrfZAVSfHvZZyXimnMtUs,omRNavtjnREFtBUixhTrUoRELlSetBCxftV){eval(" ascii
    $s12 = "function D(EmHvboMVNnNf,UjriZxfjolBldy){EmHvboMVNnNf.push(UjriZxfjolBldy);}function L4(OdilZSjDOXqBkbtP){if(FqBlDnu(OdilZSjDOXqB" ascii
    $s13 = "function XeOBtZUJicWHnzSyzRnsaGrtdayOdSRNGslVtFGWvuakWcBYPavluu(tFIedljIrrgsr,gIRuDEsKIsjYaT){ return ruGveFb[AnrPydpM[vvSUh(tFI" ascii
    $s14 = "function XeOBtZUJicWHnzSyzRnsaGrtdayOdSRNGslVtFGWvuakWcBYPavluu(tFIedljIrrgsr,gIRuDEsKIsjYaT){ return ruGveFb[AnrPydpM[vvSUh(tFI" ascii
    $s15 = "function KolrgvULFRN(iQLJuGwg,VrIrZi){return iQLJuGwg.split(VrIrZi)}" fullword ascii
    $s16 = "var u=new Array();" fullword ascii
    $s17 = "function DahUBaPuxBIVwYL(OdLiQCNdSZWWhTBzT){eval(OdLiQCNdSZWWhTBzT)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}