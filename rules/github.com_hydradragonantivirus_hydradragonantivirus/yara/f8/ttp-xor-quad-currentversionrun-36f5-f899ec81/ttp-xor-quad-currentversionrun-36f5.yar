rule TTP_XOR_QUAD_CurrentVersionRun_36f5 {
  strings:
    $key_36f5 = { 65 9a [2] 41 94 [2] 6a b8 [2] 44 9a [2] 50 81 [2] 5f 9b [2] 41 86 [2] 43 87 [2] 58 81 [2] 44 86 [2] 58 a9 }

  condition:
    any of them
}