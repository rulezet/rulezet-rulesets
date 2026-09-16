rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_99369f59b90f_5369 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\"" ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(fu" ascii
    $s3 = "n \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s4 = "n \"Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}