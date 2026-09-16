rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_cf2bd9606d39_5573 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "on f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"" ascii
    $s3 = "0(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";" ascii
    $s4 = "urn \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s5 = "on f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}