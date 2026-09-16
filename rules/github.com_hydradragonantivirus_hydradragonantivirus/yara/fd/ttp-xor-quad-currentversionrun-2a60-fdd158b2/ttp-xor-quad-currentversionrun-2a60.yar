rule TTP_XOR_QUAD_CurrentVersionRun_2a60 {
  strings:
    $key_2a60 = { 79 0f [2] 5d 01 [2] 76 2d [2] 58 0f [2] 4c 14 [2] 43 0e [2] 5d 13 [2] 5f 12 [2] 44 14 [2] 58 13 [2] 44 3c }

  condition:
    any of them
}