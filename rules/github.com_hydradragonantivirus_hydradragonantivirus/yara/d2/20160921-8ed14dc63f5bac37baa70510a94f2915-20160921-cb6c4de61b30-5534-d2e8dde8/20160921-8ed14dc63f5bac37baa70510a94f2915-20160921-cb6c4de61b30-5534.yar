rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_cb6c4de61b30_5534 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2 = "\"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s3 = "urn \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(" ascii
    $s4 = "n \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s5 = "n\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}