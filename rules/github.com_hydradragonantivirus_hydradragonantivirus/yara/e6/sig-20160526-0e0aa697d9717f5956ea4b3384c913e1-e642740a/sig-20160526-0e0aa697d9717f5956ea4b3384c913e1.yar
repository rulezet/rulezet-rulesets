rule sig_20160526_0e0aa697d9717f5956ea4b3384c913e1 {
  meta:
    description = "datamaliciousorder - file 20160526_0e0aa697d9717f5956ea4b3384c913e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "382fc2ffa6de89e40ad5a88be59c1586b9e428754e8cf6e81e016deee1d4a4fd"

  strings:
    $s1  = " (666 + Math.round((Math.pow(Math.sin(685), 2) + Math.pow(Math.cos(685), 2) - 1))-648) | PJOYZFMYwpEZXtkpONsKgXmw<< (627 + Math." ascii
    $s2  = "function fZVtmlM(hYuheIJSqvtuj) {var oFWhznAZChYpu = qWlJxlEt.join(RYXiaXaJGhx[0]);var NNXpQLIyNMwybfpV, vBfJryhcQfaCsIGlSbYiKhI" ascii
    $s3  = "round((Math.pow(Math.sin(923), 2) + Math.pow(Math.cos(923), 2) - 1))-615) | PJZaXKUVLaQEy<< (318 + Math.round((Math.pow(Math.sin" ascii
    $s4  = "function hxaKMzNUAa(xsdWVIRbMhwV,eEMZZDCvmHNvhqdxGSAw){return xsdWVIRbMhwV.charAt(eEMZZDCvmHNvhqdxGSAw);}" fullword ascii
    $s5  = "function NiMvdBwHqdYawHf(DJoIQSxDbbRWWGkLFJUf,gpPEzQxrTAuzYPQwRtfVcsWn){return String.fromCharCode(DJoIQSxDbbRWWGkLFJUf,gpPEzQxr" ascii
    $s6  = "function BjxjDfHYoByEfJwHIYlaAJ(tocCWWk,gLjgF,eYmBQeYW){return String.fromCharCode(tocCWWk,gLjgF,eYmBQeYW);}" fullword ascii
    $s7  = "function mfUMzBRHdEsc(HCxaFzbeTaUoM,oxqHjtPuDcbdtvMfzabL){return HCxaFzbeTaUoM.indexOf(oxqHjtPuDcbdtvMfzabL);}" fullword ascii
    $s8  = "function NiMvdBwHqdYawHf(DJoIQSxDbbRWWGkLFJUf,gpPEzQxrTAuzYPQwRtfVcsWn){return String.fromCharCode(DJoIQSxDbbRWWGkLFJUf,gpPEzQxr" ascii
    $s9  = "function fZVtmlM(hYuheIJSqvtuj) {var oFWhznAZChYpu = qWlJxlEt.join(RYXiaXaJGhx[0]);var NNXpQLIyNMwybfpV, vBfJryhcQfaCsIGlSbYiKhI" ascii
    $s10 = "fpV, vBfJryhcQfaCsIGlSbYiKhI, CbqrN);} while (hFkDmqmN < hYuheIJSqvtuj.length);return TYnRDkXHcMHMJth;}" fullword ascii
    $s11 = "HMJth += NiMvdBwHqdYawHf(NNXpQLIyNMwybfpV, vBfJryhcQfaCsIGlSbYiKhI);else TYnRDkXHcMHMJth += BjxjDfHYoByEfJwHIYlaAJ(NNXpQLIyNMwyb" ascii
    $s12 = "function W(oxQAEacDAIujpcXHeU){return String.fromCharCode(oxQAEacDAIujpcXHeU);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}