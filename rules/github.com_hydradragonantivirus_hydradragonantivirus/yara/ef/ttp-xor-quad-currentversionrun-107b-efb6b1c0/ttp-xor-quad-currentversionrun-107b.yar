rule TTP_XOR_QUAD_CurrentVersionRun_107b {
  strings:
    $key_107b = { 43 14 [2] 67 1a [2] 4c 36 [2] 62 14 [2] 76 0f [2] 79 15 [2] 67 08 [2] 65 09 [2] 7e 0f [2] 62 08 [2] 7e 27 }

  condition:
    any of them
}