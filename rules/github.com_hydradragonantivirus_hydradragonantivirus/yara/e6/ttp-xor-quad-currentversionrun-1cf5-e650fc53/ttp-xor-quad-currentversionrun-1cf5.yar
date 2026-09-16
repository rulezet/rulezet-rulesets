rule TTP_XOR_QUAD_CurrentVersionRun_1cf5 {
  strings:
    $key_1cf5 = { 4f 9a [2] 6b 94 [2] 40 b8 [2] 6e 9a [2] 7a 81 [2] 75 9b [2] 6b 86 [2] 69 87 [2] 72 81 [2] 6e 86 [2] 72 a9 }

  condition:
    any of them
}