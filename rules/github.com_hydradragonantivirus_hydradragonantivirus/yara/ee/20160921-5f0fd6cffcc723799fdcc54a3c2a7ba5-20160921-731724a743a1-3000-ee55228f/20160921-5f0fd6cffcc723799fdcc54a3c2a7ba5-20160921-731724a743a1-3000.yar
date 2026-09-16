rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_731724a743a1_3000 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_95ced062e0552048d29cf59daab852db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash3       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"

  strings:
    $s1 = "n\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s2 = "nction f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s3 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){retu" ascii
    $s4 = "d\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(functio" ascii
    $s5 = "unction f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s6 = "00(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh" ascii
    $s7 = "nction f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}