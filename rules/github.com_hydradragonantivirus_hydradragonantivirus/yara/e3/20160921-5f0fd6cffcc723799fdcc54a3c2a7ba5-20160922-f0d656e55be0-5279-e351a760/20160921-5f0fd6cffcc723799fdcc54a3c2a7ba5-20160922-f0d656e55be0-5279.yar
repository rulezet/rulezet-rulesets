rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160922_f0d656e55be0_5279 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "0(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";" ascii
    $s2 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";" ascii
    $s3 = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s4 = "00(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";" ascii
    $s5 = "n \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}