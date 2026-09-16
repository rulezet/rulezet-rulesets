rule sig_20160526_e92468b39fb0fce77f90c554c3e54fc5 {
  meta:
    description = "datamaliciousorder - file 20160526_e92468b39fb0fce77f90c554c3e54fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "242907630d3d700d99a9ab70cb4a77420b3aa2a0dafe3607b31ceb0acbc300b7"

  strings:
    $s1  = "function IZjQahAyqlUsK(mlyjrDAlQlWtF) {var hpSOtZbeZTjOJ = cbiekzsrtPSx.join(aCxRYVckteTArJjToE[0]);var BGSVjrTyHjv, PjTvpzMJbZF" ascii
    $s2  = "2) + Math.pow(Math.cos(118), 2) - 1))-452) & 0xff;AxPdRadSJEcWvQtXXuFeIIRn = kQkbwoHahjkr & 0xff;if (ayztXYiPAZd == (1040 + Math" ascii
    $s3  = ".round((Math.pow(Math.sin(684), 2) + Math.pow(Math.cos(684), 2) - 1))-976)) LoPZf += rh(BGSVjrTyHjv);else if (eOonIFKufXUfhVsAAH" ascii
    $s4  = "function EKdFegYBkUYwwGqEgC(gFbaaqCCRyTyzSiIhdKNHVoq,INlNfUvtUBOSanwMtE){return gFbaaqCCRyTyzSiIhdKNHVoq.charAt(INlNfUvtUBOSanwM" ascii
    $s5  = "function EKdFegYBkUYwwGqEgC(gFbaaqCCRyTyzSiIhdKNHVoq,INlNfUvtUBOSanwMtE){return gFbaaqCCRyTyzSiIhdKNHVoq.charAt(INlNfUvtUBOSanwM" ascii
    $s6  = "function VEksggyjpVjQBXsPKHseVOTu(KzJUtGAXtA,heFTxpkps,AnhChoBIvrsS){return String.fromCharCode(KzJUtGAXtA,heFTxpkps,AnhChoBIvrs" ascii
    $s7  = "rTyHjv, PjTvpzMJbZFht);else LoPZf += VEksggyjpVjQBXsPKHseVOTu(BGSVjrTyHjv, PjTvpzMJbZFht, AxPdRadSJEcWvQtXXuFeIIRn);} while (ZrA" ascii
    $s8  = "tXYIgQzhvbdIl < mlyjrDAlQlWtF.length);return LoPZf;}" fullword ascii
    $s9  = "function VEksggyjpVjQBXsPKHseVOTu(KzJUtGAXtA,heFTxpkps,AnhChoBIvrsS){return String.fromCharCode(KzJUtGAXtA,heFTxpkps,AnhChoBIvrs" ascii
    $s10 = "function BkbFOByUGDlHfiIeUSQ(AIaqqd,upxkrtmRLnxLNxBuH){return AIaqqd.indexOf(upxkrtmRLnxLNxBuH);}" fullword ascii
    $s11 = "function IZjQahAyqlUsK(mlyjrDAlQlWtF) {var hpSOtZbeZTjOJ = cbiekzsrtPSx.join(aCxRYVckteTArJjToE[0]);var BGSVjrTyHjv, PjTvpzMJbZF" ascii
    $s12 = "function rh(XRXimm){return String.fromCharCode(XRXimm);}" fullword ascii
    $s13 = "function JQVlHYuvVigQxsuItPDpV(tPVqnRLmkJonguCuHt,aZFRGMgkB){return String.fromCharCode(tPVqnRLmkJonguCuHt,aZFRGMgkB);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}