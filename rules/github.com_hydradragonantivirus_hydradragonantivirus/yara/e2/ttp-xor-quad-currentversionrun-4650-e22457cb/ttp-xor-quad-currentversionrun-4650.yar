rule TTP_XOR_QUAD_CurrentVersionRun_4650 {
  strings:
    $key_4650 = { 15 3f [2] 31 31 [2] 1a 1d [2] 34 3f [2] 20 24 [2] 2f 3e [2] 31 23 [2] 33 22 [2] 28 24 [2] 34 23 [2] 28 0c }

  condition:
    any of them
}