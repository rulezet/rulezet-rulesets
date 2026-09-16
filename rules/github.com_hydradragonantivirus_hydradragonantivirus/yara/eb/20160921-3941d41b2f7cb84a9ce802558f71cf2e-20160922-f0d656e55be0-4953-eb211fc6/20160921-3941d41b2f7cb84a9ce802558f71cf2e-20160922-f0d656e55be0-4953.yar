rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160922_f0d656e55be0_4953 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "\"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(functi" ascii
    $s2 = "urn \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s3 = "f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj" ascii
    $s4 = "g\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f" ascii
    $s5 = " \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}