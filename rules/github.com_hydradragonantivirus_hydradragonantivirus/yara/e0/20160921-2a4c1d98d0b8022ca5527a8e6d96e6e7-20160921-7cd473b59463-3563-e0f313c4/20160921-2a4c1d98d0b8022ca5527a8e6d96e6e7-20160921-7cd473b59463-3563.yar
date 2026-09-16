rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_7cd473b59463_3563 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = " \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s2 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";}" ascii
    $s3 = " \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = "ction f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return " ascii
    $s5 = "urn \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})()," ascii
    $s6 = "(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}