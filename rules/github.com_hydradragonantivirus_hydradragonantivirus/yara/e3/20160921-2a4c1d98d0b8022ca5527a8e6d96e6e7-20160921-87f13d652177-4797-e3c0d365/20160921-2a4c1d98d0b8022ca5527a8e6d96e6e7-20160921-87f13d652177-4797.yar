rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_87f13d652177_4797 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = "rn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(fu" ascii
    $s2 = "00(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\"" ascii
    $s3 = "000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s4 = " \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s5 = "00(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}