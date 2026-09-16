rule TTP_XOR_QUAD_CurrentVersionRun_d6e7 {
  strings:
    $key_d6e7 = { 85 88 [2] a1 86 [2] 8a aa [2] a4 88 [2] b0 93 [2] bf 89 [2] a1 94 [2] a3 95 [2] b8 93 [2] a4 94 [2] b8 bb }

  condition:
    any of them
}