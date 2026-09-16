rule TTP_XOR_QUAD_CurrentVersionRun_68e7 {
  strings:
    $key_68e7 = { 3b 88 [2] 1f 86 [2] 34 aa [2] 1a 88 [2] 0e 93 [2] 01 89 [2] 1f 94 [2] 1d 95 [2] 06 93 [2] 1a 94 [2] 06 bb }

  condition:
    any of them
}