rule TTP_XOR_QUAD_CurrentVersionRun_d627 {
  strings:
    $key_d627 = { 85 48 [2] a1 46 [2] 8a 6a [2] a4 48 [2] b0 53 [2] bf 49 [2] a1 54 [2] a3 55 [2] b8 53 [2] a4 54 [2] b8 7b }

  condition:
    any of them
}