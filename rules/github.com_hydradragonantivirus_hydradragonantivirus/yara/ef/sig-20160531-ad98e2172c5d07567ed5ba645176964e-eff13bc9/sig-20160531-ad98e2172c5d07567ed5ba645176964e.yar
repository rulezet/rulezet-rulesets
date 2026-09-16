rule sig_20160531_ad98e2172c5d07567ed5ba645176964e {
  meta:
    description = "datamaliciousorder - file 20160531_ad98e2172c5d07567ed5ba645176964e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf38ed1b44e69dd76db307a0434ad9d40aa2513f5f805c19104762aea656d4b9"

  strings:
    $s1  = "var FWfKq=function(){return WScript.CreateObject(sUcfQs[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function MmmEyoUEyQZXIepyvajaJOSH(OZNhaBmsL,ycapBLocz){return OZNhaBmsL.charAt(ycapBLocz);}" fullword ascii
    $s3  = "function dngRPMlMQNTpMmlClD(LVBFUbsFbysAiHIqfyczLLN,yYTGqaOKJsJFkumohgRYFSG,JJfjfC){return String.fromCharCode(LVBFUbsFbysAiHIqf" ascii
    $s4  = "function GEeAyHXYdscj(){return eqxnNCHAbB(sUcfQs[11],[2,4,8,10],sUcfQs[12]);}" fullword ascii
    $s5  = "function eqxnNCHAbB(CSQugJQmp,njLPJzuQa,SxDLRwEqjVKj){zdMTNge=CSQugJQmp.split(SxDLRwEqjVKj);kCeRjCr = sUcfQs[0];for(NGdqaVIz=0;N" ascii
    $s6  = "function TlwHVFuZS(GSbHu,YCRDAXpjd) {var nOxHlEexXk=[sUcfQs[15]];GSbHu[nOxHlEexXk[0]]" fullword ascii
    $s7  = "function eqxnNCHAbB(CSQugJQmp,njLPJzuQa,SxDLRwEqjVKj){zdMTNge=CSQugJQmp.split(SxDLRwEqjVKj);kCeRjCr = sUcfQs[0];for(NGdqaVIz=0;N" ascii
    $s8  = "function SsmfFYi(){return eqxnNCHAbB(sUcfQs[13],[0,3,6],sUcfQs[14]);}" fullword ascii
    $s9  = "(YCRDAXpjd,0x1,0x0)}function RJpGjmsJyB(tKjmbUdj,fsSOPRIfpE,MHIHRFEwOf){var OMKzIBQfjHsX=tKjmbUdj.createtextfile(fsSOPRIfpE,true" ascii
    $s10 = "function pMCypkz(){return FWfKq.ExpandEnvironmentStrings(YerPIhIBWfTzdo())}" fullword ascii
    $s11 = "var GySImaiNXrFWPW=function(){return new ActiveXObject(sUcfQs[1]);}();" fullword ascii
    $s12 = "function YerPIhIBWfTzdo(){return eqxnNCHAbB(sUcfQs[9],[1,5,7],sUcfQs[10]);}" fullword ascii
    $s13 = "(YCRDAXpjd,0x1,0x0)}function RJpGjmsJyB(tKjmbUdj,fsSOPRIfpE,MHIHRFEwOf){var OMKzIBQfjHsX=tKjmbUdj.createtextfile(fsSOPRIfpE,true" ascii
    $s14 = "function dngRPMlMQNTpMmlClD(LVBFUbsFbysAiHIqfyczLLN,yYTGqaOKJsJFkumohgRYFSG,JJfjfC){return String.fromCharCode(LVBFUbsFbysAiHIqf" ascii
    $s15 = "function OUfyYVooVu(lwIWeJXWXvbex) {var VqYBAxiazSTXXclt = TYBPN.join(sUcfQs[7]);var LfgtlKiPvU, QjTTXBsJAHNFOUvmxBuVue, OJeiaKO" ascii
    $s16 = "function cE(UTtneB){return String.fromCharCode(UTtneB);}" fullword ascii
    $s17 = "function rGHSliS(UwGgdmVLQgTHZhJM,GLghC){return String.fromCharCode(UwGgdmVLQgTHZhJM,GLghC);}" fullword ascii
    $s18 = "GdqaVIz<njLPJzuQa.length;NGdqaVIz++) {kCeRjCr+=zdMTNge[njLPJzuQa[NGdqaVIz]];}return kCeRjCr.substring(3,kCeRjCr.length);}" fullword ascii
    $s19 = "lD(LfgtlKiPvU, QjTTXBsJAHNFOUvmxBuVue, OJeiaKOgzfGOxDqTWcVTvuE);} while (QufQWJuOcgIiQUcpw < lwIWeJXWXvbex.length);return pozLHC" ascii
    $s20 = "function yGPNe(aEpMIwcYOvwc,ETgrWAoYbgSvW){return aEpMIwcYOvwc.indexOf(ETgrWAoYbgSvW);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}