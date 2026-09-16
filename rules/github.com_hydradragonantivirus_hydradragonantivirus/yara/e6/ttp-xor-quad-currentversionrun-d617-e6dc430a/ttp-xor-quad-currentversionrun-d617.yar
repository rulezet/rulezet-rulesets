rule TTP_XOR_QUAD_CurrentVersionRun_d617 {
  strings:
    $key_d617 = { 85 78 [2] a1 76 [2] 8a 5a [2] a4 78 [2] b0 63 [2] bf 79 [2] a1 64 [2] a3 65 [2] b8 63 [2] a4 64 [2] b8 4b }

  condition:
    any of them
}