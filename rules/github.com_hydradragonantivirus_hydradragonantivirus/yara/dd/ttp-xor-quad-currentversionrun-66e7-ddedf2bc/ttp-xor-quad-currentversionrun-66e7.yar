rule TTP_XOR_QUAD_CurrentVersionRun_66e7 {
  strings:
    $key_66e7 = { 35 88 [2] 11 86 [2] 3a aa [2] 14 88 [2] 00 93 [2] 0f 89 [2] 11 94 [2] 13 95 [2] 08 93 [2] 14 94 [2] 08 bb }

  condition:
    any of them
}