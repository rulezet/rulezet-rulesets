rule TTP_XOR_QUAD_CurrentVersionRun_7ee7 {
  strings:
    $key_7ee7 = { 2d 88 [2] 09 86 [2] 22 aa [2] 0c 88 [2] 18 93 [2] 17 89 [2] 09 94 [2] 0b 95 [2] 10 93 [2] 0c 94 [2] 10 bb }

  condition:
    any of them
}