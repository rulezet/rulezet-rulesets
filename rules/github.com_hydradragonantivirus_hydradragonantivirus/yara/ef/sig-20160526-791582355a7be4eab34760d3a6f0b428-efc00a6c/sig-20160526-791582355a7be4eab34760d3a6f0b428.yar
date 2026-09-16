rule sig_20160526_791582355a7be4eab34760d3a6f0b428 {
  meta:
    description = "datamaliciousorder - file 20160526_791582355a7be4eab34760d3a6f0b428.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1ee4fa11cb0bf9bd54ca36a6a409900344e8f0029e89e93172774107dc91d00"

  strings:
    $s1  = "th.cos(72), 2) - 1))-108)) DtFjfUxrVfqGH += YONHGtgFChjZzPmwT(wHUrF, TMhahPJLSrUl);else DtFjfUxrVfqGH += ZVldzjnWGWlrQZQYPZpnHT(" ascii
    $s2  = "2) - 1))-512)) DtFjfUxrVfqGH += wB(wHUrF);else if (MqiBTelHPVnnvGU == (172 + Math.round((Math.pow(Math.sin(72), 2) + Math.pow(Ma" ascii
    $s3  = "function tZgjYxTCoYF(oOHiPxAsnoTFe) {var STbTtFdctzZgBfYzvY = uscsgRuwgIzbrnKDnOr.join(xYWOEqlZldabz[0]);var wHUrF, TMhahPJLSrUl" ascii
    $s4  = "function MLdnjxGNzYLew(KzlzH,eVqNKJailXgUBGvkRZ){return KzlzH.charAt(eVqNKJailXgUBGvkRZ);}" fullword ascii
    $s5  = "function ZVldzjnWGWlrQZQYPZpnHT(dVYIgAsvYiOdAdj,rSSifmyhfowqHmakSiTvMQus,Ydpcg){return String.fromCharCode(dVYIgAsvYiOdAdj,rSSif" ascii
    $s6  = "function PUDzkQ(jsfWhfmZtWx,cgMKDLqzydkLOkDFrR){return jsfWhfmZtWx.indexOf(cgMKDLqzydkLOkDFrR);}" fullword ascii
    $s7  = "function YONHGtgFChjZzPmwT(wyhotwoBkKtvV,PqPTOGZukJBbC){return String.fromCharCode(wyhotwoBkKtvV,PqPTOGZukJBbC);}" fullword ascii
    $s8  = "function tZgjYxTCoYF(oOHiPxAsnoTFe) {var STbTtFdctzZgBfYzvY = uscsgRuwgIzbrnKDnOr.join(xYWOEqlZldabz[0]);var wHUrF, TMhahPJLSrUl" ascii
    $s9  = "function ZVldzjnWGWlrQZQYPZpnHT(dVYIgAsvYiOdAdj,rSSifmyhfowqHmakSiTvMQus,Ydpcg){return String.fromCharCode(dVYIgAsvYiOdAdj,rSSif" ascii
    $s10 = "function wB(dPZuRxCjqfatlephLRdTbSSv){return String.fromCharCode(dPZuRxCjqfatlephLRdTbSSv);}" fullword ascii
    $s11 = "wHUrF, TMhahPJLSrUl, iOoFgSsGSfxiJsIePfitZ);} while (SpfZLRAZmIwXcabmp < oOHiPxAsnoTFe.length);return DtFjfUxrVfqGH;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}