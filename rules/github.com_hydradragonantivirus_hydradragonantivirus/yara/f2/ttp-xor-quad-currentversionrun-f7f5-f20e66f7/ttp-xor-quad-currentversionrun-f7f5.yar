rule TTP_XOR_QUAD_CurrentVersionRun_f7f5 {
  strings:
    $key_f7f5 = { a4 9a [2] 80 94 [2] ab b8 [2] 85 9a [2] 91 81 [2] 9e 9b [2] 80 86 [2] 82 87 [2] 99 81 [2] 85 86 [2] 99 a9 }

  condition:
    any of them
}