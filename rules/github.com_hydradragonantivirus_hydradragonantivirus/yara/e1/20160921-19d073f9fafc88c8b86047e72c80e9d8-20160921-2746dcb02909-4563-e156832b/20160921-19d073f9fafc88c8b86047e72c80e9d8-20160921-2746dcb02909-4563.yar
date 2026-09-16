rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_2746dcb02909_4563 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash4       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash5       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash6       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash7       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = " f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s2 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\"" ascii
    $s3 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s4 = "eturn \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()," ascii
    $s5 = "n \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}