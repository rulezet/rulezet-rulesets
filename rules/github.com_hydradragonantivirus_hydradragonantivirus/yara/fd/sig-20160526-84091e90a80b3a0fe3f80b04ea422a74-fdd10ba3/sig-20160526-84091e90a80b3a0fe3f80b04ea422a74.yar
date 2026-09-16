rule sig_20160526_84091e90a80b3a0fe3f80b04ea422a74 {
  meta:
    description = "datamaliciousorder - file 20160526_84091e90a80b3a0fe3f80b04ea422a74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11de8c4a445d8fcea47d9c9a9386eaa07a107b97a1c534a656ce6150b7ec3bd6"

  strings:
    $s1  = " (490 + Math.round((Math.pow(Math.sin(720), 2) + Math.pow(Math.cos(720), 2) - 1))-426)) uGhdaoakWpbR += a(PJkiVOsV);else if (abk" ascii
    $s2  = "function fFiXtJJDDuJWZp(AULMONwRgULhk) {var ZBoztIcvsmAHCDVOwlgr = VdUgJeBjVDKfSnyrZubyNyuK.join(KaAAYW[0]);var PJkiVOsV, diQtVc" ascii
    $s3  = "function lzsZNZaZxdSfM(TrHKtJV,gcNHJBTglKwd){return TrHKtJV.charAt(gcNHJBTglKwd);}" fullword ascii
    $s4  = "function rVQPxieSzmp(xCunKzhkKIyjjcP,lkuHEkHjpvS){return xCunKzhkKIyjjcP.indexOf(lkuHEkHjpvS);}" fullword ascii
    $s5  = "function fFiXtJJDDuJWZp(AULMONwRgULhk) {var ZBoztIcvsmAHCDVOwlgr = VdUgJeBjVDKfSnyrZubyNyuK.join(KaAAYW[0]);var PJkiVOsV, diQtVc" ascii
    $s6  = "length);return uGhdaoakWpbR;}" fullword ascii
    $s7  = "function NDfoNnlUa(bMtlqTvmXlFq,RROpEZchPBlqJm){return String.fromCharCode(bMtlqTvmXlFq,RROpEZchPBlqJm);}" fullword ascii
    $s8  = "PJkiVOsV, diQtVc);else uGhdaoakWpbR += ovpmbYhVmcbzPieiur(PJkiVOsV, diQtVc, dbaeJdkUMpB);} while (rpCkGfYiOwmMQ < AULMONwRgULhk." ascii
    $s9  = "function ovpmbYhVmcbzPieiur(LRCnNYRztDpScxFNP,hJidDBXeYmN,mteiyhqbWWVv){return String.fromCharCode(LRCnNYRztDpScxFNP,hJidDBXeYmN" ascii
    $s10 = "function ovpmbYhVmcbzPieiur(LRCnNYRztDpScxFNP,hJidDBXeYmN,mteiyhqbWWVv){return String.fromCharCode(LRCnNYRztDpScxFNP,hJidDBXeYmN" ascii
    $s11 = "function a(TtvRINtTFhkTxfxR){return String.fromCharCode(TtvRINtTFhkTxfxR);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}