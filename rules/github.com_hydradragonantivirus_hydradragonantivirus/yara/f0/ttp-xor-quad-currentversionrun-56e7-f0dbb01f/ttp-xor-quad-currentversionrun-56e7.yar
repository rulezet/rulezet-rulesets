rule TTP_XOR_QUAD_CurrentVersionRun_56e7 {
  strings:
    $key_56e7 = { 05 88 [2] 21 86 [2] 0a aa [2] 24 88 [2] 30 93 [2] 3f 89 [2] 21 94 [2] 23 95 [2] 38 93 [2] 24 94 [2] 38 bb }

  condition:
    any of them
}