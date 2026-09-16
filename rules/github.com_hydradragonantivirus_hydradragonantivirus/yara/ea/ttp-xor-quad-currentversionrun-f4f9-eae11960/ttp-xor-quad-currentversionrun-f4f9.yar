rule TTP_XOR_QUAD_CurrentVersionRun_f4f9 {
  strings:
    $key_f4f9 = { a7 96 [2] 83 98 [2] a8 b4 [2] 86 96 [2] 92 8d [2] 9d 97 [2] 83 8a [2] 81 8b [2] 9a 8d [2] 86 8a [2] 9a a5 }

  condition:
    any of them
}