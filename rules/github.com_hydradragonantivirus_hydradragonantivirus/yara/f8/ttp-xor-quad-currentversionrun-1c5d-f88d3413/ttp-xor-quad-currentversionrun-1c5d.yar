rule TTP_XOR_QUAD_CurrentVersionRun_1c5d {
  strings:
    $key_1c5d = { 4f 32 [2] 6b 3c [2] 40 10 [2] 6e 32 [2] 7a 29 [2] 75 33 [2] 6b 2e [2] 69 2f [2] 72 29 [2] 6e 2e [2] 72 01 }

  condition:
    any of them
}