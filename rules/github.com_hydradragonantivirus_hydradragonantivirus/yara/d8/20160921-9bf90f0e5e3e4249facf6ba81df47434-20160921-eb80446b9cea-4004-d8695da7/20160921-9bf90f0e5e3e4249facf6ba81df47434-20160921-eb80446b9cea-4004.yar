rule _20160921_9bf90f0e5e3e4249facf6ba81df47434_20160921_eb80446b9cea_4004 {
  meta:
    description = "datamaliciousorder - from files 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash3       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f00" ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QD" ascii
    $s4 = "function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){re" ascii
    $s5 = "turn \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(" ascii
    $s6 = "00(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}