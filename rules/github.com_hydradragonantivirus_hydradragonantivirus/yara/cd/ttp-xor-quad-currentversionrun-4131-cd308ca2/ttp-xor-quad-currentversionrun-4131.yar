rule TTP_XOR_QUAD_CurrentVersionRun_4131 {
  strings:
    $key_4131 = { 12 5e [2] 36 50 [2] 1d 7c [2] 33 5e [2] 27 45 [2] 28 5f [2] 36 42 [2] 34 43 [2] 2f 45 [2] 33 42 [2] 2f 6d }

  condition:
    any of them
}