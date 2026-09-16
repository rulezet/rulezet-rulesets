rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_a65ac281dbfd_5574 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"

  strings:
    $s1 = "ion f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s2 = "(){return \"Ot\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RVb\";})" ascii
    $s3 = "urn \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(" ascii
    $s4 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000" ascii
    $s5 = "})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}