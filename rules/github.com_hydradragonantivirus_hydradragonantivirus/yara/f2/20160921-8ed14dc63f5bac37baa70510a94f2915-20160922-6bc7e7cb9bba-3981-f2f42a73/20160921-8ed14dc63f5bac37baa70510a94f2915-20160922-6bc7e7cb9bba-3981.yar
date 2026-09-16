rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160922_6bc7e7cb9bba_3981 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi" ascii
    $s2 = "(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s3 = "n \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s4 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s5 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s6 = "nction f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}