rule TTP_XOR_QUAD_CurrentVersionRun_7b7b {
  strings:
    $key_7b7b = { 28 14 [2] 0c 1a [2] 27 36 [2] 09 14 [2] 1d 0f [2] 12 15 [2] 0c 08 [2] 0e 09 [2] 15 0f [2] 09 08 [2] 15 27 }

  condition:
    any of them
}