rule TTP_XOR_QUAD_CurrentVersionRun_e740 {
  strings:
    $key_e740 = { b4 2f [2] 90 21 [2] bb 0d [2] 95 2f [2] 81 34 [2] 8e 2e [2] 90 33 [2] 92 32 [2] 89 34 [2] 95 33 [2] 89 1c }

  condition:
    any of them
}