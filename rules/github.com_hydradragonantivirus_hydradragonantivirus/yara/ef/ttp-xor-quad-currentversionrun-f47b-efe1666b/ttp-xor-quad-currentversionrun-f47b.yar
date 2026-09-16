rule TTP_XOR_QUAD_CurrentVersionRun_f47b {
  strings:
    $key_f47b = { a7 14 [2] 83 1a [2] a8 36 [2] 86 14 [2] 92 0f [2] 9d 15 [2] 83 08 [2] 81 09 [2] 9a 0f [2] 86 08 [2] 9a 27 }

  condition:
    any of them
}