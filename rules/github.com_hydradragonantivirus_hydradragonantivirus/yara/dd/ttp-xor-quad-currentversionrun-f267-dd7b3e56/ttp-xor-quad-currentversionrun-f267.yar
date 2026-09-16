rule TTP_XOR_QUAD_CurrentVersionRun_f267 {
  strings:
    $key_f267 = { a1 08 [2] 85 06 [2] ae 2a [2] 80 08 [2] 94 13 [2] 9b 09 [2] 85 14 [2] 87 15 [2] 9c 13 [2] 80 14 [2] 9c 3b }

  condition:
    any of them
}