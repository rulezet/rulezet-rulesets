rule TTP_XOR_QUAD_CurrentVersionRun_7be7 {
  strings:
    $key_7be7 = { 28 88 [2] 0c 86 [2] 27 aa [2] 09 88 [2] 1d 93 [2] 12 89 [2] 0c 94 [2] 0e 95 [2] 15 93 [2] 09 94 [2] 15 bb }

  condition:
    any of them
}