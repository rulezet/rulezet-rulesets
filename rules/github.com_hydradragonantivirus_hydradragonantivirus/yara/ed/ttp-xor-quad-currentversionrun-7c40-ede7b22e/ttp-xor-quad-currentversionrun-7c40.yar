rule TTP_XOR_QUAD_CurrentVersionRun_7c40 {
  strings:
    $key_7c40 = { 2f 2f [2] 0b 21 [2] 20 0d [2] 0e 2f [2] 1a 34 [2] 15 2e [2] 0b 33 [2] 09 32 [2] 12 34 [2] 0e 33 [2] 12 1c }

  condition:
    any of them
}