rule TTP_XOR_QUAD_CurrentVersionRun_4940 {
  strings:
    $key_4940 = { 1a 2f [2] 3e 21 [2] 15 0d [2] 3b 2f [2] 2f 34 [2] 20 2e [2] 3e 33 [2] 3c 32 [2] 27 34 [2] 3b 33 [2] 27 1c }

  condition:
    any of them
}