rule sig_20151215_96db8faf817eada96f4fc99c002e0eea {
  meta:
    description = "datamaliciousorder - file 20151215_96db8faf817eada96f4fc99c002e0eea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02802cc2c33632159679043e4d1feb530985e1a36f450e899149d0553d38ed9e"

  strings:
    $s1  = "ath.pow(Math.cos(281), 2) - 1)); while(true) { if(RUQfqLiYq[OBkCiNIdWBK] > nQoOt[OBkCiNIdWBK].length-(-501+980)/479) { break; } " ascii
    $s2  = "h.pow(Math.cos(637), 2) - 1)));} RUQfqLiYq[OBkCiNIdWBK]++;}} return RnmCdYNrmOv}" fullword ascii
    $s3  = "function KYjRUSStFzUobzMcN(nQoOt){RnmCdYNrmOv= L[1828];for(OBkCiNIdWBK=Math.round((Math.pow(Math.sin(764), 2) + Math.pow(Math.co" ascii
    $s4  = "function KYjRUSStFzUobzMcN(nQoOt){RnmCdYNrmOv= L[1828];for(OBkCiNIdWBK=Math.round((Math.pow(Math.sin(764), 2) + Math.pow(Math.co" ascii
    $s5  = "XWwT)) {return (String.fromCharCode(yoQTzRMyHgZuXWwT) + String.fromCharCode((37853+416)/781));}}" fullword ascii
    $s6  = "function T(ebLVHjLwJedE,nRCdqrKycTKLxE){ebLVHjLwJedE.push(nRCdqrKycTKLxE);}function X9(yoQTzRMyHgZuXWwT){if(znQGOWq(yoQTzRMyHgZu" ascii
    $s7  = "var L=new Array();" fullword ascii
    $s8  = "function IWTaY(CcGSYbjWwaI,MIwseKKUXxSyv,zNsGgghA){mKeI=parseInt(CcGSYbjWwaI,MIwseKKUXxSyv);CKeub=mKeI.toString(zNsGgghA);return" ascii
    $s9  = "function iYDzlQBITIq(kxsJaVTn,pdMggZ){return kxsJaVTn.split(pdMggZ)}" fullword ascii
    $s10 = "function hKlwCDZqEdWsmZb(FiVztUdZxSBJTFSYL){eval(FiVztUdZxSBJTFSYL)}" fullword ascii
    $s11 = "function yzrXRGJKmIvSVqCYbFiBYcNYjWkBuOkVQoVLLljcnHepUHnQZhqqab(DmQOBIgXMqGFh,cLeXLXqdyWcVNO){ return AWXzqYV[uAqKqCua[IWTaY(DmQ" ascii
    $s12 = "function yzrXRGJKmIvSVqCYbFiBYcNYjWkBuOkVQoVLLljcnHepUHnQZhqqab(DmQOBIgXMqGFh,cLeXLXqdyWcVNO){ return AWXzqYV[uAqKqCua[IWTaY(DmQ" ascii
    $s13 = "function IWTaY(CcGSYbjWwaI,MIwseKKUXxSyv,zNsGgghA){mKeI=parseInt(CcGSYbjWwaI,MIwseKKUXxSyv);CKeub=mKeI.toString(zNsGgghA);return" ascii
    $s14 = " CKeub;}function hKlwCDZqEdWsmZb(FiVztUdZxSBJTFSYL,ZwnURVVjAevQELvMPGHcglfchSiYwpeOcz,gUkEHKsyxRWfMoWZSSSDRtgCBQKCpSUaDBh){eval(" ascii
    $s15 = "function T(ebLVHjLwJedE,nRCdqrKycTKLxE){ebLVHjLwJedE.push(nRCdqrKycTKLxE);}function X9(yoQTzRMyHgZuXWwT){if(znQGOWq(yoQTzRMyHgZu" ascii
    $s16 = "function znQGOWq(kGoqacMhGjVcakWDJSsIBkgTvDBgbeFnsTUp) {return !isNaN(parseFloat(kGoqacMhGjVcakWDJSsIBkgTvDBgbeFnsTUp)) && isFin" ascii
    $s17 = "function znQGOWq(kGoqacMhGjVcakWDJSsIBkgTvDBgbeFnsTUp) {return !isNaN(parseFloat(kGoqacMhGjVcakWDJSsIBkgTvDBgbeFnsTUp)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}