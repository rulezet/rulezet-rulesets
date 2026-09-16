rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_4b801afbcd98_4964 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash3       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash4       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash5       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash6       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash7       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1 = "(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s2 = "f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KX" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f0" ascii
    $s4 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s5 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}