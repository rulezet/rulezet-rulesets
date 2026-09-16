rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_7cd473b59463_3737 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"S" ascii
    $s2 = "return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})()," ascii
    $s3 = "return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})()," ascii
    $s4 = " \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(func" ascii
    $s5 = " \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(funct" ascii
    $s6 = "nction f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}