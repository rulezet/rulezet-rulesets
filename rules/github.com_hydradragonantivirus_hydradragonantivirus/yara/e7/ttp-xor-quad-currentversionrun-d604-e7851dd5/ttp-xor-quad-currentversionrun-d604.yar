rule TTP_XOR_QUAD_CurrentVersionRun_d604 {
  strings:
    $key_d604 = { 85 6b [2] a1 65 [2] 8a 49 [2] a4 6b [2] b0 70 [2] bf 6a [2] a1 77 [2] a3 76 [2] b8 70 [2] a4 77 [2] b8 58 }

  condition:
    any of them
}