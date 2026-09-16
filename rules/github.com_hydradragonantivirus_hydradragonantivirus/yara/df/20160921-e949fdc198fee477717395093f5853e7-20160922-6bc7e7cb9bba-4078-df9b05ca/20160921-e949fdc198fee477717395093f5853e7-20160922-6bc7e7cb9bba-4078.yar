rule _20160921_e949fdc198fee477717395093f5853e7_20160922_6bc7e7cb9bba_4078 {
  meta:
    description = "datamaliciousorder - from files 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash2       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"I" ascii
    $s2 = ")(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(" ascii
    $s3 = "rn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s4 = "on f000(){return \"QDg\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s5 = "function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s6 = "000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}