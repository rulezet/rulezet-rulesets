rule TTP_XOR_QUAD_CurrentVersionRun_3c5b {
  strings:
    $key_3c5b = { 6f 34 [2] 4b 3a [2] 60 16 [2] 4e 34 [2] 5a 2f [2] 55 35 [2] 4b 28 [2] 49 29 [2] 52 2f [2] 4e 28 [2] 52 07 }

  condition:
    any of them
}