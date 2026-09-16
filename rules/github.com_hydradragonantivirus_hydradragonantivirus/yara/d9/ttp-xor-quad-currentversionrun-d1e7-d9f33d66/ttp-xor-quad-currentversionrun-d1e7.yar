rule TTP_XOR_QUAD_CurrentVersionRun_d1e7 {
  strings:
    $key_d1e7 = { 82 88 [2] a6 86 [2] 8d aa [2] a3 88 [2] b7 93 [2] b8 89 [2] a6 94 [2] a4 95 [2] bf 93 [2] a3 94 [2] bf bb }

  condition:
    any of them
}