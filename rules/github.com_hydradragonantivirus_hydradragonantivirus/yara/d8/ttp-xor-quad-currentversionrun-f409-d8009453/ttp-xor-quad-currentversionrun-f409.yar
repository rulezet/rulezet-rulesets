rule TTP_XOR_QUAD_CurrentVersionRun_f409 {
  strings:
    $key_f409 = { a7 66 [2] 83 68 [2] a8 44 [2] 86 66 [2] 92 7d [2] 9d 67 [2] 83 7a [2] 81 7b [2] 9a 7d [2] 86 7a [2] 9a 55 }

  condition:
    any of them
}