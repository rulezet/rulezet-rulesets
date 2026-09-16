rule TTP_XOR_QUAD_CurrentVersionRun_452c {
  strings:
    $key_452c = { 16 43 [2] 32 4d [2] 19 61 [2] 37 43 [2] 23 58 [2] 2c 42 [2] 32 5f [2] 30 5e [2] 2b 58 [2] 37 5f [2] 2b 70 }

  condition:
    any of them
}