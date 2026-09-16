rule TTP_XOR_QUAD_CurrentVersionRun_554b {
  strings:
    $key_554b = { 06 24 [2] 22 2a [2] 09 06 [2] 27 24 [2] 33 3f [2] 3c 25 [2] 22 38 [2] 20 39 [2] 3b 3f [2] 27 38 [2] 3b 17 }

  condition:
    any of them
}