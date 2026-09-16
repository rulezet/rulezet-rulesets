rule TTP_XOR_QUAD_CurrentVersionRun_2527 {
  strings:
    $key_2527 = { 76 48 [2] 52 46 [2] 79 6a [2] 57 48 [2] 43 53 [2] 4c 49 [2] 52 54 [2] 50 55 [2] 4b 53 [2] 57 54 [2] 4b 7b }

  condition:
    any of them
}