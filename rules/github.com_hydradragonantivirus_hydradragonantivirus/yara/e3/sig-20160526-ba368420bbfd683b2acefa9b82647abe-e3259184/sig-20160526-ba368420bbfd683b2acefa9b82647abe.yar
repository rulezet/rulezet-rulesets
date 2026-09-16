rule sig_20160526_ba368420bbfd683b2acefa9b82647abe {
  meta:
    description = "datamaliciousorder - file 20160526_ba368420bbfd683b2acefa9b82647abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "564daa56b489f4acf39a0b5ad2aab03d5bc6deb7c60cbd1992cf4f6f27750b90"

  strings:
    $s1  = "7), 2) + Math.pow(Math.cos(937), 2) - 1))-222)) LmfzzgckzlOmrOZEZ += UE(gCSWXUbqcsIP);else if (EhPrUuvliJAWnbaPqWGK == (842 + Ma" ascii
    $s2  = "function hmIusjvhcQRvoW(laRrsxWzXdhOb) {var IHPXzeISxF = vrGWgzpU.join(AYncUrgIdVszTe[0]);var gCSWXUbqcsIP, VndKnjDB, fElmGhWVJb" ascii
    $s3  = "function ZIgyyPFClfVViMro(XoYRH,KomXLyDlWsLYoaztjimFGFfQ){return XoYRH.charAt(KomXLyDlWsLYoaztjimFGFfQ);}" fullword ascii
    $s4  = "th);return LmfzzgckzlOmrOZEZ;}" fullword ascii
    $s5  = "function UE(jwQTAOz){return String.fromCharCode(jwQTAOz);}" fullword ascii
    $s6  = "function QIilKmaqQljQgFL(UJjTuUYFQMPbIcpOo,rprHODNlbldY){return UJjTuUYFQMPbIcpOo.indexOf(rprHODNlbldY);}" fullword ascii
    $s7  = "function YbKbqDTBsA(HLcvCVa,NVgbeRsqcLdJDePPFL){return String.fromCharCode(HLcvCVa,NVgbeRsqcLdJDePPFL);}" fullword ascii
    $s8  = "njDB);else LmfzzgckzlOmrOZEZ += NBUDxgni(gCSWXUbqcsIP, VndKnjDB, fElmGhWVJbBrd);} while (ykGworLwhWnnGFlokU < laRrsxWzXdhOb.leng" ascii
    $s9  = "function NBUDxgni(nUWEBCUNEyuhrHbiWoczZcYX,sdVwso,BfjdqaZ){return String.fromCharCode(nUWEBCUNEyuhrHbiWoczZcYX,sdVwso,BfjdqaZ);}" ascii
    $s10 = "function hmIusjvhcQRvoW(laRrsxWzXdhOb) {var IHPXzeISxF = vrGWgzpU.join(AYncUrgIdVszTe[0]);var gCSWXUbqcsIP, VndKnjDB, fElmGhWVJb" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}