rule TTP_XOR_QUAD_CurrentVersionRun_32e7 {
  strings:
    $key_32e7 = { 61 88 [2] 45 86 [2] 6e aa [2] 40 88 [2] 54 93 [2] 5b 89 [2] 45 94 [2] 47 95 [2] 5c 93 [2] 40 94 [2] 5c bb }

  condition:
    any of them
}