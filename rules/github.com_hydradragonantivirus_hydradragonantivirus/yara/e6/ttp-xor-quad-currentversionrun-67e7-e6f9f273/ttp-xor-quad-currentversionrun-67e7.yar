rule TTP_XOR_QUAD_CurrentVersionRun_67e7 {
  strings:
    $key_67e7 = { 34 88 [2] 10 86 [2] 3b aa [2] 15 88 [2] 01 93 [2] 0e 89 [2] 10 94 [2] 12 95 [2] 09 93 [2] 15 94 [2] 09 bb }

  condition:
    any of them
}