rule TTP_XOR_QUAD_CurrentVersionRun_c7e6 {
  strings:
    $key_c7e6 = { 94 89 [2] b0 87 [2] 9b ab [2] b5 89 [2] a1 92 [2] ae 88 [2] b0 95 [2] b2 94 [2] a9 92 [2] b5 95 [2] a9 ba }

  condition:
    any of them
}