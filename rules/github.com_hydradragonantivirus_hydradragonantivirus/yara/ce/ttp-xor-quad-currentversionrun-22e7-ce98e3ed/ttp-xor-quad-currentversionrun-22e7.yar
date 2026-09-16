rule TTP_XOR_QUAD_CurrentVersionRun_22e7 {
  strings:
    $key_22e7 = { 71 88 [2] 55 86 [2] 7e aa [2] 50 88 [2] 44 93 [2] 4b 89 [2] 55 94 [2] 57 95 [2] 4c 93 [2] 50 94 [2] 4c bb }

  condition:
    any of them
}