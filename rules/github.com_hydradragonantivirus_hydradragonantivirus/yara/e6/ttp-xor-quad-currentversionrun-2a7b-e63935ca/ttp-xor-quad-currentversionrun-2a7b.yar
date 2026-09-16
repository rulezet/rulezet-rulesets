rule TTP_XOR_QUAD_CurrentVersionRun_2a7b {
  strings:
    $key_2a7b = { 79 14 [2] 5d 1a [2] 76 36 [2] 58 14 [2] 4c 0f [2] 43 15 [2] 5d 08 [2] 5f 09 [2] 44 0f [2] 58 08 [2] 44 27 }

  condition:
    any of them
}