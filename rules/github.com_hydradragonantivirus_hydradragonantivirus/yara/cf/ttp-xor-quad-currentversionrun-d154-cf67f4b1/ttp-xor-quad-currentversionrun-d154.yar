rule TTP_XOR_QUAD_CurrentVersionRun_d154 {
  strings:
    $key_d154 = { 82 3b [2] a6 35 [2] 8d 19 [2] a3 3b [2] b7 20 [2] b8 3a [2] a6 27 [2] a4 26 [2] bf 20 [2] a3 27 [2] bf 08 }

  condition:
    any of them
}