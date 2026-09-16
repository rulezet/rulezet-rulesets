rule TTP_XOR_QUAD_CurrentVersionRun_365d {
  strings:
    $key_365d = { 65 32 [2] 41 3c [2] 6a 10 [2] 44 32 [2] 50 29 [2] 5f 33 [2] 41 2e [2] 43 2f [2] 58 29 [2] 44 2e [2] 58 01 }

  condition:
    any of them
}