rule TTP_XOR_QUAD_CurrentVersionRun_f255 {
  strings:
    $key_f255 = { a1 3a [2] 85 34 [2] ae 18 [2] 80 3a [2] 94 21 [2] 9b 3b [2] 85 26 [2] 87 27 [2] 9c 21 [2] 80 26 [2] 9c 09 }

  condition:
    any of them
}