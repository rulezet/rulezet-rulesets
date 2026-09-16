rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_97fcc16be1aa_1905 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1  = "turn \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})()," ascii
    $s2  = "tion f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s3  = "unction f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s4  = "tion f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s5  = "n f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s6  = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s7  = " \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(func" ascii
    $s8  = "0(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc" ascii
    $s9  = "000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn" ascii
    $s10 = "\"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}