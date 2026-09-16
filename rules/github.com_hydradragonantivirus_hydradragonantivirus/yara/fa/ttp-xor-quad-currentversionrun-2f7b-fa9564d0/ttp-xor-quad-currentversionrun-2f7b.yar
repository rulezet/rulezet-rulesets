rule TTP_XOR_QUAD_CurrentVersionRun_2f7b {
  strings:
    $key_2f7b = { 7c 14 [2] 58 1a [2] 73 36 [2] 5d 14 [2] 49 0f [2] 46 15 [2] 58 08 [2] 5a 09 [2] 41 0f [2] 5d 08 [2] 41 27 }

  condition:
    any of them
}