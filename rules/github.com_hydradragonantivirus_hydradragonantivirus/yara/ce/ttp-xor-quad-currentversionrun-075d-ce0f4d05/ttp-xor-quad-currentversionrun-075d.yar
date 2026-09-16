rule TTP_XOR_QUAD_CurrentVersionRun_075d {
  strings:
    $key_075d = { 54 32 [2] 70 3c [2] 5b 10 [2] 75 32 [2] 61 29 [2] 6e 33 [2] 70 2e [2] 72 2f [2] 69 29 [2] 75 2e [2] 69 01 }

  condition:
    any of them
}