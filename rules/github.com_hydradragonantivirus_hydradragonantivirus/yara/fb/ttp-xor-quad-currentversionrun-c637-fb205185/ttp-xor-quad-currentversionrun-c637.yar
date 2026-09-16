rule TTP_XOR_QUAD_CurrentVersionRun_c637 {
  strings:
    $key_c637 = { 95 58 [2] b1 56 [2] 9a 7a [2] b4 58 [2] a0 43 [2] af 59 [2] b1 44 [2] b3 45 [2] a8 43 [2] b4 44 [2] a8 6b }

  condition:
    any of them
}