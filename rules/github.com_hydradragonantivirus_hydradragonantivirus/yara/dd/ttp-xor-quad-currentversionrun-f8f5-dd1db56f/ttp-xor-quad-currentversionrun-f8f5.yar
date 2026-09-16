rule TTP_XOR_QUAD_CurrentVersionRun_f8f5 {
  strings:
    $key_f8f5 = { ab 9a [2] 8f 94 [2] a4 b8 [2] 8a 9a [2] 9e 81 [2] 91 9b [2] 8f 86 [2] 8d 87 [2] 96 81 [2] 8a 86 [2] 96 a9 }

  condition:
    any of them
}