rule TTP_XOR_QUAD_CurrentVersionRun_45e7 {
  strings:
    $key_45e7 = { 16 88 [2] 32 86 [2] 19 aa [2] 37 88 [2] 23 93 [2] 2c 89 [2] 32 94 [2] 30 95 [2] 2b 93 [2] 37 94 [2] 2b bb }

  condition:
    any of them
}