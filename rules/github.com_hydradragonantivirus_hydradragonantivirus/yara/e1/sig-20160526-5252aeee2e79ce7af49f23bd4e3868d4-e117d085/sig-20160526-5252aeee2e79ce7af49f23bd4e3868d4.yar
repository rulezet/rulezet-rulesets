rule sig_20160526_5252aeee2e79ce7af49f23bd4e3868d4 {
  meta:
    description = "datamaliciousorder - file 20160526_5252aeee2e79ce7af49f23bd4e3868d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37be7a2897b3f74e9fb8dd606143f44da95d9411dff9c0dd71839e0c91a6cbb2"

  strings:
    $s1  = "os(851), 2) - 1))-672)) flRYAikcgjMJDRC += SLsXAnAKcRafunGvxjtw(oRvCvhvDbtUzgGsjD, EcsPpLbXoWOdpSgy);else flRYAikcgjMJDRC += Zmh" ascii
    $s2  = "function CicwmRAHKiaG(ZFjsnBhZOsTTE) {var ouxpkri = MoTYiWhnDgFtcnwWw.join(HcpBXEJkVDFvxG[0]);var oRvCvhvDbtUzgGsjD, EcsPpLbXoWO" ascii
    $s3  = "gjMJDRC += KR(oRvCvhvDbtUzgGsjD);else if (BDEsZsLSmyMwEaeYlLC == (736 + Math.round((Math.pow(Math.sin(851), 2) + Math.pow(Math.c" ascii
    $s4  = "function pYygNr(cLPhhgaKYhSqBgpwWUWtC,cUVJWvLtNwYrUm){return cLPhhgaKYhSqBgpwWUWtC.charAt(cUVJWvLtNwYrUm);}" fullword ascii
    $s5  = "function KR(ATbLrbRHeHTnBxUX){return String.fromCharCode(ATbLrbRHeHTnBxUX);}" fullword ascii
    $s6  = "function ZmhxiksEUL(OZyxWjeJiqFOgzYl,AMCwYRdYGQixcghdMwtDe,eheeYqsQhiarnSYeIqPSs){return String.fromCharCode(OZyxWjeJiqFOgzYl,AM" ascii
    $s7  = "function ccStTaQoYSY(bXuDeKrwscMmpdEWBk,EzGuQprUWCHkwqjpnNUUkRnB){return bXuDeKrwscMmpdEWBk.indexOf(EzGuQprUWCHkwqjpnNUUkRnB);}" fullword ascii
    $s8  = "function SLsXAnAKcRafunGvxjtw(bZQoWOB,cEUBSYDr){return String.fromCharCode(bZQoWOB,cEUBSYDr);}" fullword ascii
    $s9  = "function CicwmRAHKiaG(ZFjsnBhZOsTTE) {var ouxpkri = MoTYiWhnDgFtcnwWw.join(HcpBXEJkVDFvxG[0]);var oRvCvhvDbtUzgGsjD, EcsPpLbXoWO" ascii
    $s10 = "function ZmhxiksEUL(OZyxWjeJiqFOgzYl,AMCwYRdYGQixcghdMwtDe,eheeYqsQhiarnSYeIqPSs){return String.fromCharCode(OZyxWjeJiqFOgzYl,AM" ascii
    $s11 = "xiksEUL(oRvCvhvDbtUzgGsjD, EcsPpLbXoWOdpSgy, BVdimgmxPCPsqLRPBANYGTI);} while (fteGVzFfepVYca < ZFjsnBhZOsTTE.length);return flR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}