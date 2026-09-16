rule _20160921_8621b60975e0be691f97b2f5849011b9_20160921_a1c2a36f9932_407 {
  meta:
    description = "datamaliciousorder - from files 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash2       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash3       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"

  strings:
    $s1  = "urn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s2  = "n \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s3  = "000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii
    $s4  = "ction f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){retu" ascii
    $s5  = "eturn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})()," ascii
    $s6  = "rn \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s7  = " \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s8  = "00(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";" ascii
    $s9  = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii
    $s10 = " f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MM" ascii
    $s11 = "n f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii
    $s12 = "\"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTs\";})(),(func" ascii
    $s13 = "rn \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s14 = "rn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s15 = "rn \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s16 = "unction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s17 = "tion f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s18 = "(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})" ascii
    $s19 = "ion f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s20 = "00(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}