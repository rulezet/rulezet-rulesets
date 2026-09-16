rule TTP_XOR_QUAD_CurrentVersionRun_d177 {
  strings:
    $key_d177 = { 82 18 [2] a6 16 [2] 8d 3a [2] a3 18 [2] b7 03 [2] b8 19 [2] a6 04 [2] a4 05 [2] bf 03 [2] a3 04 [2] bf 2b }

  condition:
    any of them
}