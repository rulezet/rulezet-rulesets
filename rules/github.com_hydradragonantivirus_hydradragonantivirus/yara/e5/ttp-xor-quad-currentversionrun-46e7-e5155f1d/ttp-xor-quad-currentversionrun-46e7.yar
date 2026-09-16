rule TTP_XOR_QUAD_CurrentVersionRun_46e7 {
  strings:
    $key_46e7 = { 15 88 [2] 31 86 [2] 1a aa [2] 34 88 [2] 20 93 [2] 2f 89 [2] 31 94 [2] 33 95 [2] 28 93 [2] 34 94 [2] 28 bb }

  condition:
    any of them
}