rule sig_20160527_562e58fe4464b07f6ec01d94679592ea {
  meta:
    description = "datamaliciousorder - file 20160527_562e58fe4464b07f6ec01d94679592ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7675330b169fbba4926488b73acb2e38c5d2c20521d5baff69ba33316b9eb396"

  strings:
    $s1  = "function cRRLUJ() {return WScript;}function RJmwpvFhimY(){return LRXKdpQBtpEX.ExpandEnvironmentStrings(cYfXMTDSi())}" fullword ascii
    $s2  = "function RQQAVTLZR(icJQRL,ApgrScOjzeNi){return icJQRL.charAt(ApgrScOjzeNi);}" fullword ascii
    $s3  = "function eemJGJJl(vmCsiinjuKtTd,fhbAGEonAFS) {var Cvollv=[eOvHxZKhLYaDjTSiU[15]];vmCsiinjuKtTd[Cvollv[0]](fhbAGEonAFS,0x1,0x0)}" fullword ascii
    $s4  = "function gEcDFnIhmdEhgj(glgIyip,iQNOwIZhNbnqSsAUE,HUrykluBOdZfpRYT){return String.fromCharCode(glgIyip,iQNOwIZhNbnqSsAUE,HUryklu" ascii
    $s5  = "or(jeIRiWlYhZkFG=0;jeIRiWlYhZkFG<rLEyj.length;jeIRiWlYhZkFG++) {jknYZsSEpRDJs+=epUnYw[rLEyj[jeIRiWlYhZkFG]];}return jknYZsSEpRDJ" ascii
    $s6  = "function BwRsAStVuI(HzUIsUYsEq,rLEyj,fyNllcrzPgCx){epUnYw=HzUIsUYsEq.split(fyNllcrzPgCx);jknYZsSEpRDJs = eOvHxZKhLYaDjTSiU[14];f" ascii
    $s7  = "var UqzHNxroKaDkv = uxVXTM.createtextfile(LRXKdpQBtpEX.ExpandEnvironmentStrings(eOvHxZKhLYaDjTSiU[2]+eOvHxZKhLYaDjTSiU[3])+Strin" ascii
    $s8  = "var uxVXTM=function(){return new ActiveXObject(eOvHxZKhLYaDjTSiU[0]);}();" fullword ascii
    $s9  = "function gEcDFnIhmdEhgj(glgIyip,iQNOwIZhNbnqSsAUE,HUrykluBOdZfpRYT){return String.fromCharCode(glgIyip,iQNOwIZhNbnqSsAUE,HUryklu" ascii
    $s10 = "function cYfXMTDSi(){return BwRsAStVuI(eOvHxZKhLYaDjTSiU[8],[1,5,7],eOvHxZKhLYaDjTSiU[9]);}" fullword ascii
    $s11 = "function KmrmpOAfhveMEkihSnbwwDBZ(BNqZRBhbWSStqRpJCOaj,NSPnK){return BNqZRBhbWSStqRpJCOaj.indexOf(NSPnK);}" fullword ascii
    $s12 = "push(\"v\");mdXxXDFiAWehcMPWWvUeLaWw.push(\"w\");mdXxXDFiAWehcMPWWvUeLaWw.push(\"x\");mdXxXDFiAWehcMPWWvUeLaWw.push(\"y\");mdXxX" ascii
    $s13 = "function yrKZbpcyOG(){return BwRsAStVuI(eOvHxZKhLYaDjTSiU[12],[0,3,6],eOvHxZKhLYaDjTSiU[13]);}" fullword ascii
    $s14 = "g.fromCharCode(92)+eOvHxZKhLYaDjTSiU[4],true);" fullword ascii
    $s15 = "var LRXKdpQBtpEX=function(){return cRRLUJ().CreateObject(eOvHxZKhLYaDjTSiU[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s16 = "function CZ(seBuMeSCsaHUALIH){return String.fromCharCode(seBuMeSCsaHUALIH);}" fullword ascii
    $s17 = "HECSOTGFBItn, QOAXrqYdWKMcowxfEYy, jZFOXtgd);} while (nGdVREgPdBHzSOEHKxOOJ < SUUTIoWsilSXn.length);return NIuVDCqr;}" fullword ascii
    $s18 = "function BwRsAStVuI(HzUIsUYsEq,rLEyj,fyNllcrzPgCx){epUnYw=HzUIsUYsEq.split(fyNllcrzPgCx);jknYZsSEpRDJs = eOvHxZKhLYaDjTSiU[14];f" ascii
    $s19 = "function EbOabdy(SUUTIoWsilSXn) {var dSNsbdOmYXHlwKlXJZSnO = mdXxXDFiAWehcMPWWvUeLaWw.join(eOvHxZKhLYaDjTSiU[6]);var YpHECSOTGFB" ascii
    $s20 = "function XLZbUNPEdqAwvHcKckPb(njbkGqwxNxDmvdEFM,sYHTnaMhCopWIbWhROekyT){return String.fromCharCode(njbkGqwxNxDmvdEFM,sYHTnaMhCop" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}