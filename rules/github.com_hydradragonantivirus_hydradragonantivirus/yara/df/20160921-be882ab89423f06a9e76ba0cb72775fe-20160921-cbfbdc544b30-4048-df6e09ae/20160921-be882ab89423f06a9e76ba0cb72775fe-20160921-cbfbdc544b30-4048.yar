rule _20160921_be882ab89423f06a9e76ba0cb72775fe_20160921_cbfbdc544b30_4048 {
  meta:
    description = "datamaliciousorder - from files 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_cbfbdc544b309301bc71d300d7726545.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash2       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"

  strings:
    $s1 = " \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s2 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f0" ascii
    $s3 = "rn \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(fun" ascii
    $s4 = "),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"QDg\";})(),(function f000(){" ascii
    $s5 = "Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh\";})(),(function" ascii
    $s6 = "n f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}