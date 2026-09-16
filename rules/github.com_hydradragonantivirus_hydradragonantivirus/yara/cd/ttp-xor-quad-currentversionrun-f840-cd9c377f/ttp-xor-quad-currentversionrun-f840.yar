rule TTP_XOR_QUAD_CurrentVersionRun_f840 {
  strings:
    $key_f840 = { ab 2f [2] 8f 21 [2] a4 0d [2] 8a 2f [2] 9e 34 [2] 91 2e [2] 8f 33 [2] 8d 32 [2] 96 34 [2] 8a 33 [2] 96 1c }

  condition:
    any of them
}