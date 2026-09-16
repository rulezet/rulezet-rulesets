rule TTP_XOR_QUAD_CurrentVersionRun_2d7b {
  strings:
    $key_2d7b = { 7e 14 [2] 5a 1a [2] 71 36 [2] 5f 14 [2] 4b 0f [2] 44 15 [2] 5a 08 [2] 58 09 [2] 43 0f [2] 5f 08 [2] 43 27 }

  condition:
    any of them
}