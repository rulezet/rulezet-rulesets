rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_9ed8ba5d12b4_3301 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = "})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MMz\";})(),(function f000" ascii
    $s2 = "ction f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){ret" ascii
    $s4 = "on f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return " ascii
    $s5 = "Gn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s6 = "n f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}