rule sig_20151209_ce3635ecb013a0b579874aab28a158ff {
  meta:
    description = "datamaliciousorder - file 20151209_ce3635ecb013a0b579874aab28a158ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca85d1e473d10c494443903a9085d1184523b88b04ae44383beeafeb5a88800c"

  strings:
    $s1  = "function HBrRfyl(aONusqmNyHPaYAMcpHbAZiozNnYslEvaHzZN) {return !isNaN(parseFloat(aONusqmNyHPaYAMcpHbAZiozNnYslEvaHzZN)) && isFin" ascii
    $s2  = "function HBrRfyl(aONusqmNyHPaYAMcpHbAZiozNnYslEvaHzZN) {return !isNaN(parseFloat(aONusqmNyHPaYAMcpHbAZiozNnYslEvaHzZN)) && isFin" ascii
    $s3  = " paecq;}function JnyCxBrlfvhPcvw(grEMGkWyADrWxwxMf){eval(grEMGkWyADrWxwxMf)}" fullword ascii
    $s4  = "function nRgWHxZQWmvWYrhSF(bxzEX){bxNNlyqJkeb= '';for(VmJWIRJtarT=(-548+548)/499; VmJWIRJtarT < (1050+730)/890; VmJWIRJtarT++) {" ascii
    $s5  = "function eboZg(cjNngwDAeFc,KeBcfDilekvGB,jVNNfOLc){Qzfs=parseInt(cjNngwDAeFc,KeBcfDilekvGB);paecq=Qzfs.toString(jVNNfOLc);return" ascii
    $s6  = "function eboZg(cjNngwDAeFc,KeBcfDilekvGB,jVNNfOLc){Qzfs=parseInt(cjNngwDAeFc,KeBcfDilekvGB);paecq=Qzfs.toString(jVNNfOLc);return" ascii
    $s7  = "]++;}} return bxNNlyqJkeb}" fullword ascii
    $s8  = "function XTmdgplLhjKnUVmNYAHPkcoCDJMUCtUorTnQAtWEvKqXAvNqhQnQmC(qKrzMJhcOdUyZ,NZhDfiFxiboLWi){ return CQhOy[eboZg(qKrzMJhcOdUyZ[" ascii
    $s9  = "function nRgWHxZQWmvWYrhSF(bxzEX){bxNNlyqJkeb= '';for(VmJWIRJtarT=(-548+548)/499; VmJWIRJtarT < (1050+730)/890; VmJWIRJtarT++) {" ascii
    $s10 = "BmSSuMCcn[VmJWIRJtarT]=(-312+312)/114; while(true) { if(BmSSuMCcn[VmJWIRJtarT] > bxzEX[VmJWIRJtarT].length-(-325+504)/179) { bre" ascii
    $s11 = "function XTmdgplLhjKnUVmNYAHPkcoCDJMUCtUorTnQAtWEvKqXAvNqhQnQmC(qKrzMJhcOdUyZ,NZhDfiFxiboLWi){ return CQhOy[eboZg(qKrzMJhcOdUyZ[" ascii
    $s12 = "function JIgSHZEAEek(XpnSMOnk,UNRtot){return XpnSMOnk.split(UNRtot)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}