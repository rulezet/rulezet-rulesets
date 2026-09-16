rule TTP_XOR_QUAD_CurrentVersionRun_f1f8 {
  strings:
    $key_f1f8 = { a2 97 [2] 86 99 [2] ad b5 [2] 83 97 [2] 97 8c [2] 98 96 [2] 86 8b [2] 84 8a [2] 9f 8c [2] 83 8b [2] 9f a4 }

  condition:
    any of them
}