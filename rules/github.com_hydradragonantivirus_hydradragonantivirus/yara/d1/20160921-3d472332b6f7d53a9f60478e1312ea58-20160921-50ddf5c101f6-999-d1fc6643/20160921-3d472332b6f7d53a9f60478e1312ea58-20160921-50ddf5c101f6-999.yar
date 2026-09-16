rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_50ddf5c101f6_999 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"

  strings:
    $s1  = "urn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s2  = "(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3  = "{return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";}" ascii
    $s4  = "00(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";" ascii
    $s5  = "tion f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6  = "eturn \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s7  = "00(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\"" ascii
    $s8  = "0(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";" ascii
    $s9  = " f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi" ascii
    $s10 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"S" ascii
    $s11 = "u\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s12 = "n f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s13 = "Lk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s14 = " f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GG" ascii
    $s15 = "\"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s16 = "{return \"Go\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})" ascii
    $s17 = "SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s18 = "),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii
    $s19 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}