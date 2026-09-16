rule TTP_XOR_QUAD_CurrentVersionRun_25e7 {
  strings:
    $key_25e7 = { 76 88 [2] 52 86 [2] 79 aa [2] 57 88 [2] 43 93 [2] 4c 89 [2] 52 94 [2] 50 95 [2] 4b 93 [2] 57 94 [2] 4b bb }

  condition:
    any of them
}