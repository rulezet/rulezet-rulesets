rule TTP_XOR_QUAD_CurrentVersionRun_457b {
  strings:
    $key_457b = { 16 14 [2] 32 1a [2] 19 36 [2] 37 14 [2] 23 0f [2] 2c 15 [2] 32 08 [2] 30 09 [2] 2b 0f [2] 37 08 [2] 2b 27 }

  condition:
    any of them
}