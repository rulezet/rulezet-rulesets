rule TTP_XOR_QUAD_CurrentVersionRun_d16b {
  strings:
    $key_d16b = { 82 04 [2] a6 0a [2] 8d 26 [2] a3 04 [2] b7 1f [2] b8 05 [2] a6 18 [2] a4 19 [2] bf 1f [2] a3 18 [2] bf 37 }

  condition:
    any of them
}