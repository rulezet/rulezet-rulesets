rule TTP_XOR_QUAD_CurrentVersionRun_f27b {
  strings:
    $key_f27b = { a1 14 [2] 85 1a [2] ae 36 [2] 80 14 [2] 94 0f [2] 9b 15 [2] 85 08 [2] 87 09 [2] 9c 0f [2] 80 08 [2] 9c 27 }

  condition:
    any of them
}