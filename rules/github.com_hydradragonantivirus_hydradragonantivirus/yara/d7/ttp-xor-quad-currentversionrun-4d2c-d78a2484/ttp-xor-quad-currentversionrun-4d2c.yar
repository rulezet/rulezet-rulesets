rule TTP_XOR_QUAD_CurrentVersionRun_4d2c {
  strings:
    $key_4d2c = { 1e 43 [2] 3a 4d [2] 11 61 [2] 3f 43 [2] 2b 58 [2] 24 42 [2] 3a 5f [2] 38 5e [2] 23 58 [2] 3f 5f [2] 23 70 }

  condition:
    any of them
}