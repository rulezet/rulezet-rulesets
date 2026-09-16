rule TTP_XOR_QUAD_CurrentVersionRun_2a7d {
  strings:
    $key_2a7d = { 79 12 [2] 5d 1c [2] 76 30 [2] 58 12 [2] 4c 09 [2] 43 13 [2] 5d 0e [2] 5f 0f [2] 44 09 [2] 58 0e [2] 44 21 }

  condition:
    any of them
}