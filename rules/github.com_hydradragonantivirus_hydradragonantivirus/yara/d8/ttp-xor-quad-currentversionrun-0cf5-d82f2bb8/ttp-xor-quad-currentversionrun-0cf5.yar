rule TTP_XOR_QUAD_CurrentVersionRun_0cf5 {
  strings:
    $key_0cf5 = { 5f 9a [2] 7b 94 [2] 50 b8 [2] 7e 9a [2] 6a 81 [2] 65 9b [2] 7b 86 [2] 79 87 [2] 62 81 [2] 7e 86 [2] 62 a9 }

  condition:
    any of them
}