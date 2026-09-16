rule TTP_XOR_QUAD_CurrentVersionRun_f239 {
  strings:
    $key_f239 = { a1 56 [2] 85 58 [2] ae 74 [2] 80 56 [2] 94 4d [2] 9b 57 [2] 85 4a [2] 87 4b [2] 9c 4d [2] 80 4a [2] 9c 65 }

  condition:
    any of them
}