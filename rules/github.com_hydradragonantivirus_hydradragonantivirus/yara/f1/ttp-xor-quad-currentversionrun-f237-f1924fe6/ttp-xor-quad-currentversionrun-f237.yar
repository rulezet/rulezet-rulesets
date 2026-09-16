rule TTP_XOR_QUAD_CurrentVersionRun_f237 {
  strings:
    $key_f237 = { a1 58 [2] 85 56 [2] ae 7a [2] 80 58 [2] 94 43 [2] 9b 59 [2] 85 44 [2] 87 45 [2] 9c 43 [2] 80 44 [2] 9c 6b }

  condition:
    any of them
}