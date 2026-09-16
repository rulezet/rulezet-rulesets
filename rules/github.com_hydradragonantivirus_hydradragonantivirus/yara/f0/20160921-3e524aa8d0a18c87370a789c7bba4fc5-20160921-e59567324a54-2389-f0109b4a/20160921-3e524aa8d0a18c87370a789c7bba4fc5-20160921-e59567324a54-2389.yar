rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_e59567324a54_2389 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "ction f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){retur" ascii
    $s2 = "00(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(functi" ascii
    $s4 = "turn \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s5 = "0(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";}" ascii
    $s6 = ",(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s7 = "on f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return " ascii
    $s8 = "f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}