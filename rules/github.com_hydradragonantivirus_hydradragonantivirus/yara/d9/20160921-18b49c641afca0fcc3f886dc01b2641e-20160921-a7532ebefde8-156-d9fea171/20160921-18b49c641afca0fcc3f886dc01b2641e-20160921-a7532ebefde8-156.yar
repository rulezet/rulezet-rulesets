rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_a7532ebefde8_156 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash3       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1  = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(fu" ascii
    $s2  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sq\";})()" ascii
    $s3  = "nction f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii
    $s4  = "eturn \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5  = ",(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){" ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(func" ascii
    $s7  = "000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\"" ascii
    $s8  = "\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Qj\";})(),(function f" ascii
    $s9  = "rn \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s10 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s11 = "){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";}" ascii
    $s12 = "b\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s13 = "n \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s14 = "f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GG" ascii
    $s15 = "00(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\"" ascii
    $s16 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"R" ascii
    $s17 = "\"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"DYx\";})(),(func" ascii
    $s18 = "})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(" ascii
    $s19 = "\"Br\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(func" ascii
    $s20 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}