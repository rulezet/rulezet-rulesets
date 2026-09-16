rule TTP_XOR_QUAD_CurrentVersionRun_4140 {
  strings:
    $key_4140 = { 12 2f [2] 36 21 [2] 1d 0d [2] 33 2f [2] 27 34 [2] 28 2e [2] 36 33 [2] 34 32 [2] 2f 34 [2] 33 33 [2] 2f 1c }

  condition:
    any of them
}