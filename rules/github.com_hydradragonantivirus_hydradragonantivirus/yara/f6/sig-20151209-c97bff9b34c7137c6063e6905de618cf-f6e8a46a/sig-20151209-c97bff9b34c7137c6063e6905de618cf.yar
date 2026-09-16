rule sig_20151209_c97bff9b34c7137c6063e6905de618cf {
  meta:
    description = "datamaliciousorder - file 20151209_c97bff9b34c7137c6063e6905de618cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8468d3cc092be534a845032d81ce87c77de65cb4753c585766e1489ced72ff50"

  strings:
    $s1  = "function WhawMcm(KArAumiJowrTrUHiFJaVdXNEccHjUQpQlmuV) {return !isNaN(parseFloat(KArAumiJowrTrUHiFJaVdXNEccHjUQpQlmuV)) && isFin" ascii
    $s2  = "function WhawMcm(KArAumiJowrTrUHiFJaVdXNEccHjUQpQlmuV) {return !isNaN(parseFloat(KArAumiJowrTrUHiFJaVdXNEccHjUQpQlmuV)) && isFin" ascii
    $s3  = "function VtBNJubXFOTvfkYQY(XgKSN){RUDCxnlHhMR= '';for(KeaeRmeawrW=(-98+98)/805; KeaeRmeawrW < (900+388)/644; KeaeRmeawrW++) {QWa" ascii
    $s4  = "}} return RUDCxnlHhMR}" fullword ascii
    $s5  = "kJWYnH[KeaeRmeawrW]=(-658+658)/876; while(true) { if(QWakJWYnH[KeaeRmeawrW] > XgKSN[KeaeRmeawrW].length-(104+454)/558) { break; " ascii
    $s6  = "function VtBNJubXFOTvfkYQY(XgKSN){RUDCxnlHhMR= '';for(KeaeRmeawrW=(-98+98)/805; KeaeRmeawrW < (900+388)/644; KeaeRmeawrW++) {QWa" ascii
    $s7  = "function XqoJZSgLYty(umDLqliB,lYjuuV){return umDLqliB.split(lYjuuV)}" fullword ascii
    $s8  = "function AgVRr(WGLdKctApyM,JjQWNzpdTuiLf,pACyzQfw){RUAQ=parseInt(WGLdKctApyM,JjQWNzpdTuiLf);DxdLZ=RUAQ.toString(pACyzQfw);return" ascii
    $s9  = "function JIUJWzCZODqtuQPraSFqPcXmtaBkzwJJyIDMVvgMrzgLMSrSzzMAQf(CXpotHmGJtLWO,lMQcmKGBdKJiIU){ return YIgDC[AgVRr(CXpotHmGJtLWO[" ascii
    $s10 = " DxdLZ;}function neHZrgVrFGgfiPY(ZvWGvBUkkNWLDIteC){eval(ZvWGvBUkkNWLDIteC)}" fullword ascii
    $s11 = "function AgVRr(WGLdKctApyM,JjQWNzpdTuiLf,pACyzQfw){RUAQ=parseInt(WGLdKctApyM,JjQWNzpdTuiLf);DxdLZ=RUAQ.toString(pACyzQfw);return" ascii
    $s12 = "function JIUJWzCZODqtuQPraSFqPcXmtaBkzwJJyIDMVvgMrzgLMSrSzzMAQf(CXpotHmGJtLWO,lMQcmKGBdKJiIU){ return YIgDC[AgVRr(CXpotHmGJtLWO[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}