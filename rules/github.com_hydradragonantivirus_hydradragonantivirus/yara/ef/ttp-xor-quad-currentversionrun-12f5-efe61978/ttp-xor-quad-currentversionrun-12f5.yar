rule TTP_XOR_QUAD_CurrentVersionRun_12f5 {
  strings:
    $key_12f5 = { 41 9a [2] 65 94 [2] 4e b8 [2] 60 9a [2] 74 81 [2] 7b 9b [2] 65 86 [2] 67 87 [2] 7c 81 [2] 60 86 [2] 7c a9 }

  condition:
    any of them
}