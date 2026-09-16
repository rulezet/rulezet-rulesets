rule TTP_XOR_QUAD_CurrentVersionRun_c6d2 {
  strings:
    $key_c6d2 = { 95 bd [2] b1 b3 [2] 9a 9f [2] b4 bd [2] a0 a6 [2] af bc [2] b1 a1 [2] b3 a0 [2] a8 a6 [2] b4 a1 [2] a8 8e }

  condition:
    any of them
}