rule TTP_XOR_QUAD_CurrentVersionRun_d14b {
  strings:
    $key_d14b = { 82 24 [2] a6 2a [2] 8d 06 [2] a3 24 [2] b7 3f [2] b8 25 [2] a6 38 [2] a4 39 [2] bf 3f [2] a3 38 [2] bf 17 }

  condition:
    any of them
}