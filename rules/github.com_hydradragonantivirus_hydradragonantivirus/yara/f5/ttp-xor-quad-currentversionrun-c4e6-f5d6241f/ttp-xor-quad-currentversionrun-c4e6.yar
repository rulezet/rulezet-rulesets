rule TTP_XOR_QUAD_CurrentVersionRun_c4e6 {
  strings:
    $key_c4e6 = { 97 89 [2] b3 87 [2] 98 ab [2] b6 89 [2] a2 92 [2] ad 88 [2] b3 95 [2] b1 94 [2] aa 92 [2] b6 95 [2] aa ba }

  condition:
    any of them
}