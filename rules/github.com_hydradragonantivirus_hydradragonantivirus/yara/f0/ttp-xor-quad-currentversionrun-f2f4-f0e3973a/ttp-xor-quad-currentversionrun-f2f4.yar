rule TTP_XOR_QUAD_CurrentVersionRun_f2f4 {
  strings:
    $key_f2f4 = { a1 9b [2] 85 95 [2] ae b9 [2] 80 9b [2] 94 80 [2] 9b 9a [2] 85 87 [2] 87 86 [2] 9c 80 [2] 80 87 [2] 9c a8 }

  condition:
    any of them
}