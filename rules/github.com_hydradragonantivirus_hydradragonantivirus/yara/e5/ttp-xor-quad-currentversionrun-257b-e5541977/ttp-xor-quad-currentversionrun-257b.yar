rule TTP_XOR_QUAD_CurrentVersionRun_257b {
  strings:
    $key_257b = { 76 14 [2] 52 1a [2] 79 36 [2] 57 14 [2] 43 0f [2] 4c 15 [2] 52 08 [2] 50 09 [2] 4b 0f [2] 57 08 [2] 4b 27 }

  condition:
    any of them
}