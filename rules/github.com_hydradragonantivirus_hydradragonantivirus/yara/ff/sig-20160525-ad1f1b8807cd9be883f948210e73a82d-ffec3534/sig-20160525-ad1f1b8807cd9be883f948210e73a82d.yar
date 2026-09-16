rule sig_20160525_ad1f1b8807cd9be883f948210e73a82d {
  meta:
    description = "datamaliciousorder - file 20160525_ad1f1b8807cd9be883f948210e73a82d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe62ab2f18d02a6b7588b2479238fd41d582b77ffd95a0cc37c32e52a61a0ad7"

  strings:
    $s1  = "h.pow(Math.cos(359), 2) - 1))-444)) qrJpZUDVgDI += jtUoMMukNVzbOJ(LuZFawDIoOzYDkFqoxvZn, EvaqmM);else qrJpZUDVgDI += OEbioVigwSq" ascii
    $s2  = "function afHhtyWq(NpngRkBVuLnJR) {var mUrmgiuUVaswPYmEjPvJCbB = YGbfr.join(TERyrUTC[0]);var LuZFawDIoOzYDkFqoxvZn, EvaqmM, FWhpW" ascii
    $s3  = "rJpZUDVgDI += cp(LuZFawDIoOzYDkFqoxvZn);else if (OjfBYzytkDuyBRuqncuqjaGs == (508 + Math.round((Math.pow(Math.sin(359), 2) + Mat" ascii
    $s4  = "function BEcPn(bUPaMyarqjAQwRXsA,vtWChaRFLNcmoOjJxZRWnx){return bUPaMyarqjAQwRXsA.charAt(vtWChaRFLNcmoOjJxZRWnx);}" fullword ascii
    $s5  = "function BlmtfKOilHHAiqEeZl(agYzPVwzBeLCXyhQ,bDMFTPCACeeHkXO){return agYzPVwzBeLCXyhQ.indexOf(bDMFTPCACeeHkXO);}" fullword ascii
    $s6  = "LkUdtqGXxw(LuZFawDIoOzYDkFqoxvZn, EvaqmM, FWhpWh);} while (taDeNaiBnkzjkygm < NpngRkBVuLnJR.length);return qrJpZUDVgDI;}" fullword ascii
    $s7  = "function OEbioVigwSqLkUdtqGXxw(kmEGaTN,syOBMfFUZSpcnOzAXTwlwkUR,qVzrCDJjECVulT){return String.fromCharCode(kmEGaTN,syOBMfFUZSpcn" ascii
    $s8  = "function afHhtyWq(NpngRkBVuLnJR) {var mUrmgiuUVaswPYmEjPvJCbB = YGbfr.join(TERyrUTC[0]);var LuZFawDIoOzYDkFqoxvZn, EvaqmM, FWhpW" ascii
    $s9  = "function jtUoMMukNVzbOJ(HkuIZpmGapYqZLb,WgtXIOiZwcHRzSOgKA){return String.fromCharCode(HkuIZpmGapYqZLb,WgtXIOiZwcHRzSOgKA);}" fullword ascii
    $s10 = "function OEbioVigwSqLkUdtqGXxw(kmEGaTN,syOBMfFUZSpcnOzAXTwlwkUR,qVzrCDJjECVulT){return String.fromCharCode(kmEGaTN,syOBMfFUZSpcn" ascii
    $s11 = "function cp(YIOuRutQPBTUAewqILIKFNAm){return String.fromCharCode(YIOuRutQPBTUAewqILIKFNAm);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}