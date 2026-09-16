rule TTP_XOR_QUAD_CurrentVersionRun_3940 {
  strings:
    $key_3940 = { 6a 2f [2] 4e 21 [2] 65 0d [2] 4b 2f [2] 5f 34 [2] 50 2e [2] 4e 33 [2] 4c 32 [2] 57 34 [2] 4b 33 [2] 57 1c }

  condition:
    any of them
}