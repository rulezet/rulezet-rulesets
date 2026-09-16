rule TTP_XOR_QUAD_CurrentVersionRun_e75d {
  strings:
    $key_e75d = { b4 32 [2] 90 3c [2] bb 10 [2] 95 32 [2] 81 29 [2] 8e 33 [2] 90 2e [2] 92 2f [2] 89 29 [2] 95 2e [2] 89 01 }

  condition:
    any of them
}