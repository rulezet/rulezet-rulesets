rule TTP_XOR_QUAD_CurrentVersionRun_367c {
  strings:
    $key_367c = { 65 13 [2] 41 1d [2] 6a 31 [2] 44 13 [2] 50 08 [2] 5f 12 [2] 41 0f [2] 43 0e [2] 58 08 [2] 44 0f [2] 58 20 }

  condition:
    any of them
}