rule TTP_XOR_QUAD_CurrentVersionRun_f44b {
  strings:
    $key_f44b = { a7 24 [2] 83 2a [2] a8 06 [2] 86 24 [2] 92 3f [2] 9d 25 [2] 83 38 [2] 81 39 [2] 9a 3f [2] 86 38 [2] 9a 17 }

  condition:
    any of them
}