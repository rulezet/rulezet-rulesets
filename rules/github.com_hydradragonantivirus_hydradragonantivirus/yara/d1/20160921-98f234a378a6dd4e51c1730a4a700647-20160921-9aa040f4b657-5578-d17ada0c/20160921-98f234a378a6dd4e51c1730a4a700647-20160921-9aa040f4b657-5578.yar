rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_5578 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash3       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s2 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s3 = " \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(func" ascii
    $s4 = "turn \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s5 = "(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}