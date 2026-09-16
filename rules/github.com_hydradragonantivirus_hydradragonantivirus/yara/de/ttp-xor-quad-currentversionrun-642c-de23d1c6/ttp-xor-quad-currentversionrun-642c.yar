rule TTP_XOR_QUAD_CurrentVersionRun_642c {
  strings:
    $key_642c = { 37 43 [2] 13 4d [2] 38 61 [2] 16 43 [2] 02 58 [2] 0d 42 [2] 13 5f [2] 11 5e [2] 0a 58 [2] 16 5f [2] 0a 70 }

  condition:
    any of them
}