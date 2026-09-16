rule TTP_XOR_QUAD_CurrentVersionRun_2540 {
  strings:
    $key_2540 = { 76 2f [2] 52 21 [2] 79 0d [2] 57 2f [2] 43 34 [2] 4c 2e [2] 52 33 [2] 50 32 [2] 4b 34 [2] 57 33 [2] 4b 1c }

  condition:
    any of them
}