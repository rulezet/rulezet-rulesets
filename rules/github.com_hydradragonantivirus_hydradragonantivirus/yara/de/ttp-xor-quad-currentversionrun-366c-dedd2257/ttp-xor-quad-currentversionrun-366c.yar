rule TTP_XOR_QUAD_CurrentVersionRun_366c {
  strings:
    $key_366c = { 65 03 [2] 41 0d [2] 6a 21 [2] 44 03 [2] 50 18 [2] 5f 02 [2] 41 1f [2] 43 1e [2] 58 18 [2] 44 1f [2] 58 30 }

  condition:
    any of them
}