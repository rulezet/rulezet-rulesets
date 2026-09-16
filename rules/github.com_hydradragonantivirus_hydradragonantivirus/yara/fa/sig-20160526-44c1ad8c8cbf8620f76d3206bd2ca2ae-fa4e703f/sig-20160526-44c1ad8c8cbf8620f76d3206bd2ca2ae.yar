rule sig_20160526_44c1ad8c8cbf8620f76d3206bd2ca2ae {
  meta:
    description = "datamaliciousorder - file 20160526_44c1ad8c8cbf8620f76d3206bd2ca2ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b30c4e88b5ed8526b616eec931ba964fc9e426c8979d2e5c11c84b56da24156"

  strings:
    $s1  = "bSwxOcwib += Lh(xUfbl);else if (XCBlD == (97 + Math.round((Math.pow(Math.sin(306), 2) + Math.pow(Math.cos(306), 2) - 1))-33)) pX" ascii
    $s2  = "function TRCQhZB(ceeFsRtEaaKsO) {var RRAZS = vrOJeb.join(vXuqAfa[0]);var xUfbl, lfKYuULL, QSsAUSoJDKGZRegn, pofEbQH, AFiASot, OR" ascii
    $s3  = "function QHzwFWbjjgtrcIioIHyriTq(LXHOBdLdOzwdm,XVQnsCNwNqzSZWNDTcEFjo){return LXHOBdLdOzwdm.charAt(XVQnsCNwNqzSZWNDTcEFjo);}" fullword ascii
    $s4  = "function wtOrHoNneo(nSeDo,DAjoJFjdw){return String.fromCharCode(nSeDo,DAjoJFjdw);}" fullword ascii
    $s5  = "WDSgn < ceeFsRtEaaKsO.length);return pXuCnSDbSwxOcwib;}" fullword ascii
    $s6  = "function TRCQhZB(ceeFsRtEaaKsO) {var RRAZS = vrOJeb.join(vXuqAfa[0]);var xUfbl, lfKYuULL, QSsAUSoJDKGZRegn, pofEbQH, AFiASot, OR" ascii
    $s7  = "function IEqOIUA(vLOdBXzMySNzm,bgaFBJLtLoP,UzKgbk){return String.fromCharCode(vLOdBXzMySNzm,bgaFBJLtLoP,UzKgbk);}" fullword ascii
    $s8  = "uCnSDbSwxOcwib += wtOrHoNneo(xUfbl, lfKYuULL);else pXuCnSDbSwxOcwib += IEqOIUA(xUfbl, lfKYuULL, QSsAUSoJDKGZRegn);} while (YjAZi" ascii
    $s9  = "function Lh(WyVusge){return String.fromCharCode(WyVusge);}" fullword ascii
    $s10 = "function KzRlrvtUNBRftcqmDW(OrVWtrsVtzel,doatK){return OrVWtrsVtzel.indexOf(doatK);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}