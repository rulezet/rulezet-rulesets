rule TTP_XOR_QUAD_CurrentVersionRun_f275 {
  strings:
    $key_f275 = { a1 1a [2] 85 14 [2] ae 38 [2] 80 1a [2] 94 01 [2] 9b 1b [2] 85 06 [2] 87 07 [2] 9c 01 [2] 80 06 [2] 9c 29 }

  condition:
    any of them
}