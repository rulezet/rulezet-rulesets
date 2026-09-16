rule TTP_XOR_QUAD_CurrentVersionRun_f0e8 {
  strings:
    $key_f0e8 = { a3 87 [2] 87 89 [2] ac a5 [2] 82 87 [2] 96 9c [2] 99 86 [2] 87 9b [2] 85 9a [2] 9e 9c [2] 82 9b [2] 9e b4 }

  condition:
    any of them
}