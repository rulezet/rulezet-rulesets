rule TTP_XOR_QUAD_CurrentVersionRun_d677 {
  strings:
    $key_d677 = { 85 18 [2] a1 16 [2] 8a 3a [2] a4 18 [2] b0 03 [2] bf 19 [2] a1 04 [2] a3 05 [2] b8 03 [2] a4 04 [2] b8 2b }

  condition:
    any of them
}