rule TTP_XOR_QUAD_CurrentVersionRun_74e7 {
  strings:
    $key_74e7 = { 27 88 [2] 03 86 [2] 28 aa [2] 06 88 [2] 12 93 [2] 1d 89 [2] 03 94 [2] 01 95 [2] 1a 93 [2] 06 94 [2] 1a bb }

  condition:
    any of them
}