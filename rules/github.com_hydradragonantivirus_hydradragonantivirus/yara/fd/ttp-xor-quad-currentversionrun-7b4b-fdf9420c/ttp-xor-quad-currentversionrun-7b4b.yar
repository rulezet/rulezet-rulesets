rule TTP_XOR_QUAD_CurrentVersionRun_7b4b {
  strings:
    $key_7b4b = { 28 24 [2] 0c 2a [2] 27 06 [2] 09 24 [2] 1d 3f [2] 12 25 [2] 0c 38 [2] 0e 39 [2] 15 3f [2] 09 38 [2] 15 17 }

  condition:
    any of them
}