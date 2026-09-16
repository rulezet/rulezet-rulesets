rule sig_20160527_993458a50b50b3255f09ff0475f3fa38 {
  meta:
    description = "datamaliciousorder - file 20160527_993458a50b50b3255f09ff0475f3fa38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd8db40c4b06796741f8b1f7f28a259b3798119c987e039ca6c9eb1795dab2dc"

  strings:
    $s1  = "function vRUTQcROVU() {return WScript;}function McbzgGskVd(){return iZkWABh.ExpandEnvironmentStrings(THJjOU())}" fullword ascii
    $s2  = "function ILadKKmOsfkxUSvd(KyNbsVuwLbbnecMgTiRFJWmO,cPrGLTOheKl){return KyNbsVuwLbbnecMgTiRFJWmO.charAt(cPrGLTOheKl);}" fullword ascii
    $s3  = "function vqIXUpHOPeBUEni(tocNxxKrbPQtWRGfSi,tsXswJVahmeTAuthiyGy){return String.fromCharCode(tocNxxKrbPQtWRGfSi,tsXswJVahmeTAuth" ascii
    $s4  = "function vqIXUpHOPeBUEni(tocNxxKrbPQtWRGfSi,tsXswJVahmeTAuthiyGy){return String.fromCharCode(tocNxxKrbPQtWRGfSi,tsXswJVahmeTAuth" ascii
    $s5  = "AgZCVDDTJU=0;AgZCVDDTJU<QwPPIKvqDGcSk.length;AgZCVDDTJU++) {xVfDLeGij+=RVuBHx[QwPPIKvqDGcSk[AgZCVDDTJU]];}return xVfDLeGij.subst" ascii
    $s6  = "function THJjOU(){return ccMEWKARDuHy(PcGKwaLLRbLS[8],[1,5,7],PcGKwaLLRbLS[9]);}" fullword ascii
    $s7  = "function SuTdRnaWmCVzMY(){return ccMEWKARDuHy(PcGKwaLLRbLS[10],[2,4,8,10],PcGKwaLLRbLS[11]);}" fullword ascii
    $s8  = "eKpR);} while (SOYrcRjAdjA < emQpcIAvwZZcy.length);return BarwAPwrmwbquecUypy;}" fullword ascii
    $s9  = "var JklXuwURqcmXAW=function(){return new ActiveXObject(PcGKwaLLRbLS[0]);}();" fullword ascii
    $s10 = "function VowJwilMsGDa(emQpcIAvwZZcy) {var PgSNp = tveIxtPqZLzFz.join(PcGKwaLLRbLS[6]);var XpmOyGYHuuoSRtYZRtjSbHU, iyYuBZhiIzHHf" ascii
    $s11 = "(92)+PcGKwaLLRbLS[4],true);" fullword ascii
    $s12 = "function NK(XOdQGuyrySwacOvhu){return String.fromCharCode(XOdQGuyrySwacOvhu);}" fullword ascii
    $s13 = "ring(3,xVfDLeGij.length);}" fullword ascii
    $s14 = "function ljiAE(zLvyuh,GyWojapMsXlCj) {var cdULl=[PcGKwaLLRbLS[15]];zLvyuh[cdULl[0]](GyWojapMsXlCj,0x1,0x0)}" fullword ascii
    $s15 = "function ccMEWKARDuHy(KNnuBc,QwPPIKvqDGcSk,WkAhsMaJMcWlpb){RVuBHx=KNnuBc.split(WkAhsMaJMcWlpb);xVfDLeGij = PcGKwaLLRbLS[14];for(" ascii
    $s16 = "var iZkWABh=function(){return vRUTQcROVU().CreateObject(PcGKwaLLRbLS[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = ", iyYuBZhiIzHHfgZEJmFSxp);else BarwAPwrmwbquecUypy += NbdGfGLHSER(XpmOyGYHuuoSRtYZRtjSbHU, iyYuBZhiIzHHfgZEJmFSxp, syMouxzAWRHhk" ascii
    $s18 = "var wfUzxX = JklXuwURqcmXAW.createtextfile(iZkWABh.ExpandEnvironmentStrings(PcGKwaLLRbLS[2]+PcGKwaLLRbLS[3])+String.fromCharCode" ascii
    $s19 = "cUypy += NK(XpmOyGYHuuoSRtYZRtjSbHU);else if (rXAIXQlTfDic == 64) BarwAPwrmwbquecUypy += vqIXUpHOPeBUEni(XpmOyGYHuuoSRtYZRtjSbHU" ascii
    $s20 = "function NbdGfGLHSER(YXmAouMUlGSWATHxWDWnxYF,UrBpQhElAOfn,YlNtakuJFax){return String.fromCharCode(YXmAouMUlGSWATHxWDWnxYF,UrBpQh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}