rule _20160921_8ac006dedc6205f05757feeef6cd894a_20160921_d4f0c091f748_5514 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash3       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "\"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s2 = "(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";}" ascii
    $s3 = "function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s4 = "n \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}