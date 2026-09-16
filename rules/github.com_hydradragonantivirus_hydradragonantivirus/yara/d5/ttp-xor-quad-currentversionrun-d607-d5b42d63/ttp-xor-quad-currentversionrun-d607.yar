rule TTP_XOR_QUAD_CurrentVersionRun_d607 {
  strings:
    $key_d607 = { 85 68 [2] a1 66 [2] 8a 4a [2] a4 68 [2] b0 73 [2] bf 69 [2] a1 74 [2] a3 75 [2] b8 73 [2] a4 74 [2] b8 5b }

  condition:
    any of them
}