rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_98f234a378a6_5366 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash3       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"

  strings:
    $s1 = "f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GG" ascii
    $s2 = " \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s3 = "g\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f" ascii
    $s4 = "tion f000(){return \"KDh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s5 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}