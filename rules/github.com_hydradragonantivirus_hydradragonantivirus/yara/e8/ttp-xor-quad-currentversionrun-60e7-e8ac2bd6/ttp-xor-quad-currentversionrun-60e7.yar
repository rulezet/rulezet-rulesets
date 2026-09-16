rule TTP_XOR_QUAD_CurrentVersionRun_60e7 {
  strings:
    $key_60e7 = { 33 88 [2] 17 86 [2] 3c aa [2] 12 88 [2] 06 93 [2] 09 89 [2] 17 94 [2] 15 95 [2] 0e 93 [2] 12 94 [2] 0e bb }

  condition:
    any of them
}