rule TTP_XOR_QUAD_CurrentVersionRun_76a3 {
  strings:
    $key_76a3 = { 25 cc [2] 01 c2 [2] 2a ee [2] 04 cc [2] 10 d7 [2] 1f cd [2] 01 d0 [2] 03 d1 [2] 18 d7 [2] 04 d0 [2] 18 ff }

  condition:
    any of them
}