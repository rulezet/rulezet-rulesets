rule TTP_XOR_QUAD_CurrentVersionRun_76a8 {
  strings:
    $key_76a8 = { 25 c7 [2] 01 c9 [2] 2a e5 [2] 04 c7 [2] 10 dc [2] 1f c6 [2] 01 db [2] 03 da [2] 18 dc [2] 04 db [2] 18 f4 }

  condition:
    any of them
}