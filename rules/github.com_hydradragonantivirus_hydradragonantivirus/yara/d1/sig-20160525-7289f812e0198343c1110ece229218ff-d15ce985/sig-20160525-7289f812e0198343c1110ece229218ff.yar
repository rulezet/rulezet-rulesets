rule sig_20160525_7289f812e0198343c1110ece229218ff {
  meta:
    description = "datamaliciousorder - file 20160525_7289f812e0198343c1110ece229218ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f761f3ec57b0e5865d7870218383a0bc782cd9a787dad265fa2d9deb856b7181"

  strings:
    $s1  = "772 + Math.round((Math.pow(Math.sin(693), 2) + Math.pow(Math.cos(693), 2) - 1))-754) | HnTjp<< (766 + Math.round((Math.pow(Math." ascii
    $s2  = "AUHD);else if (GzDHCciWGYuWvMOWqa == (958 + Math.round((Math.pow(Math.sin(568), 2) + Math.pow(Math.cos(568), 2) - 1))-894)) frhW" ascii
    $s3  = "function AIUUyAtbD(fbLMuFAeCCfRL) {var hrEMIvPpyCMyUBIh = AMSTFWTsUHxe.join(TlbJiqc[0]);var LGvxyCAUHD, xZFeyoFz, gRNKCCQUDaxP, " ascii
    $s4  = "th.pow(Math.cos(443), 2) - 1))-672) | GzDHCciWGYuWvMOWqa;LGvxyCAUHD = pSRIGnTyFUFunqwzhwBNMMd>> (155 + Math.round((Math.pow(Math" ascii
    $s5  = "function jIQksGKgFHGhS(qhMTwROXOnInzvBJqxpQFuB,SyWvw){return qhMTwROXOnInzvBJqxpQFuB.charAt(SyWvw);}" fullword ascii
    $s6  = "function JREuEvzDgtpzUv(pONotjQRtBknkmGlnTlmlxJ,BaKofnnFeowfXeeGopcJC,NrNJNSKNroV){return String.fromCharCode(pONotjQRtBknkmGlnT" ascii
    $s7  = "function JREuEvzDgtpzUv(pONotjQRtBknkmGlnTlmlxJ,BaKofnnFeowfXeeGopcJC,NrNJNSKNroV){return String.fromCharCode(pONotjQRtBknkmGlnT" ascii
    $s8  = "function Ax(emajRvKeEi){return String.fromCharCode(emajRvKeEi);}" fullword ascii
    $s9  = "function oxTcvV(xTSjAVVnyCmKqsTBM,aOFAQ){return xTSjAVVnyCmKqsTBM.indexOf(aOFAQ);}" fullword ascii
    $s10 = "function SRnwLHlS(OmIzxWMUc,TzaYKS){return String.fromCharCode(OmIzxWMUc,TzaYKS);}" fullword ascii
    $s11 = "axP);} while (khwxO < fbLMuFAeCCfRL.length);return frhWJUBaToBVONWIQNpRC;}" fullword ascii
    $s12 = "JUBaToBVONWIQNpRC += SRnwLHlS(LGvxyCAUHD, xZFeyoFz);else frhWJUBaToBVONWIQNpRC += JREuEvzDgtpzUv(LGvxyCAUHD, xZFeyoFz, gRNKCCQUD" ascii
    $s13 = "function AIUUyAtbD(fbLMuFAeCCfRL) {var hrEMIvPpyCMyUBIh = AMSTFWTsUHxe.join(TlbJiqc[0]);var LGvxyCAUHD, xZFeyoFz, gRNKCCQUDaxP, " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}