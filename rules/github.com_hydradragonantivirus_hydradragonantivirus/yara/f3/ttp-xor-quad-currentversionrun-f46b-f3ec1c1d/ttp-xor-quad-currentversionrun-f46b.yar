rule TTP_XOR_QUAD_CurrentVersionRun_f46b {
  strings:
    $key_f46b = { a7 04 [2] 83 0a [2] a8 26 [2] 86 04 [2] 92 1f [2] 9d 05 [2] 83 18 [2] 81 19 [2] 9a 1f [2] 86 18 [2] 9a 37 }

  condition:
    any of them
}