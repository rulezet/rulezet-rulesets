rule TTP_XOR_QUAD_CurrentVersionRun_f225 {
  strings:
    $key_f225 = { a1 4a [2] 85 44 [2] ae 68 [2] 80 4a [2] 94 51 [2] 9b 4b [2] 85 56 [2] 87 57 [2] 9c 51 [2] 80 56 [2] 9c 79 }

  condition:
    any of them
}