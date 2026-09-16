rule TTP_XOR_QUAD_CurrentVersionRun_275b {
  strings:
    $key_275b = { 74 34 [2] 50 3a [2] 7b 16 [2] 55 34 [2] 41 2f [2] 4e 35 [2] 50 28 [2] 52 29 [2] 49 2f [2] 55 28 [2] 49 07 }

  condition:
    any of them
}