rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_c79bcee11e76_3979 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "\"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s2 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s3 = "\"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s4 = "function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s5 = "Na\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s6 = "nction f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}