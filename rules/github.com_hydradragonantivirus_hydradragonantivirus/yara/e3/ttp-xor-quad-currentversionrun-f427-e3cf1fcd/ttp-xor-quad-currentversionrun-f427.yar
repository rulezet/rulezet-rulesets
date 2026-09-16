rule TTP_XOR_QUAD_CurrentVersionRun_f427 {
  strings:
    $key_f427 = { a7 48 [2] 83 46 [2] a8 6a [2] 86 48 [2] 92 53 [2] 9d 49 [2] 83 54 [2] 81 55 [2] 9a 53 [2] 86 54 [2] 9a 7b }

  condition:
    any of them
}