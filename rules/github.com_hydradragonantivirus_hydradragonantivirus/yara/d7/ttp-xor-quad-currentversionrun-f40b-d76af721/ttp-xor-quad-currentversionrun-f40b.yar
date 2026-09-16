rule TTP_XOR_QUAD_CurrentVersionRun_f40b {
  strings:
    $key_f40b = { a7 64 [2] 83 6a [2] a8 46 [2] 86 64 [2] 92 7f [2] 9d 65 [2] 83 78 [2] 81 79 [2] 9a 7f [2] 86 78 [2] 9a 57 }

  condition:
    any of them
}