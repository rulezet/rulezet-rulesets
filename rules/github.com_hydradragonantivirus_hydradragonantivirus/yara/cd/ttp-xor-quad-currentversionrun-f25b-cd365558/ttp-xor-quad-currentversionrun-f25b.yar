rule TTP_XOR_QUAD_CurrentVersionRun_f25b {
  strings:
    $key_f25b = { a1 34 [2] 85 3a [2] ae 16 [2] 80 34 [2] 94 2f [2] 9b 35 [2] 85 28 [2] 87 29 [2] 9c 2f [2] 80 28 [2] 9c 07 }

  condition:
    any of them
}