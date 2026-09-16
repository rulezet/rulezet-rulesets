rule sig_20160526_dbacda5ca4c70bc538a98a5d171e2879 {
  meta:
    description = "datamaliciousorder - file 20160526_dbacda5ca4c70bc538a98a5d171e2879.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38db1ef8bee5d42ab396a03661c888cd9c2e07bdf555792fc6239c53a94ab94a"

  strings:
    $s1  = "function APMwZBv(fWPJyZkrYwpZq) {var bUQbWecYoNNaog = ssCYGWyWuFFFheySPWHc.join(FwzrxqVzXyXqgEoBo[0]);var FpCDjUyQR, IaJRCf, vvs" ascii
    $s2  = "+= UZ(FpCDjUyQR);else if (LEOmSisfMZrsYCUhFIwE == (851 + Math.round((Math.pow(Math.sin(418), 2) + Math.pow(Math.cos(418), 2) - 1" ascii
    $s3  = "function NqZfKVTbDXNzY(qmtLxyRBMD,WZrRDaJXInMEOMKxNBhLP){return qmtLxyRBMD.charAt(WZrRDaJXInMEOMKxNBhLP);}" fullword ascii
    $s4  = "le (lbIpkpSr < fWPJyZkrYwpZq.length);return VqKojekCfHPd;}" fullword ascii
    $s5  = "function UZ(cWwgE){return String.fromCharCode(cWwgE);}" fullword ascii
    $s6  = "function JSEiGqyrq(uCEhSnxXhHTvkeqnvwmdUqTy,rNhvJwMevN,hOqACGthmFazYlpggHlnIJyB){return String.fromCharCode(uCEhSnxXhHTvkeqnvwmd" ascii
    $s7  = "))-787)) VqKojekCfHPd += FoperHXYHaC(FpCDjUyQR, IaJRCf);else VqKojekCfHPd += JSEiGqyrq(FpCDjUyQR, IaJRCf, vvsEhnijlHRkkCr);} whi" ascii
    $s8  = "function APMwZBv(fWPJyZkrYwpZq) {var bUQbWecYoNNaog = ssCYGWyWuFFFheySPWHc.join(FwzrxqVzXyXqgEoBo[0]);var FpCDjUyQR, IaJRCf, vvs" ascii
    $s9  = "function lNsoByT(Mxcre,uLQmHccDFomkGprNf){return Mxcre.indexOf(uLQmHccDFomkGprNf);}" fullword ascii
    $s10 = "function JSEiGqyrq(uCEhSnxXhHTvkeqnvwmdUqTy,rNhvJwMevN,hOqACGthmFazYlpggHlnIJyB){return String.fromCharCode(uCEhSnxXhHTvkeqnvwmd" ascii
    $s11 = "function FoperHXYHaC(DMxfQwbNelslmp,AmpqRhRY){return String.fromCharCode(DMxfQwbNelslmp,AmpqRhRY);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}