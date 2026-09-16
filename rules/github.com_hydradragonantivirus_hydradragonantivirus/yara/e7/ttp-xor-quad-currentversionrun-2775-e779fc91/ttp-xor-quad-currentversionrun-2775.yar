rule TTP_XOR_QUAD_CurrentVersionRun_2775 {
  strings:
    $key_2775 = { 74 1a [2] 50 14 [2] 7b 38 [2] 55 1a [2] 41 01 [2] 4e 1b [2] 50 06 [2] 52 07 [2] 49 01 [2] 55 06 [2] 49 29 }

  condition:
    any of them
}