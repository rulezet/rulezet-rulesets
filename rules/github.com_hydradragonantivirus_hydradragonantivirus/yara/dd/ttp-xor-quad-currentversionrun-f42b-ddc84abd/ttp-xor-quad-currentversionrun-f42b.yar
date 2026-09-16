rule TTP_XOR_QUAD_CurrentVersionRun_f42b {
  strings:
    $key_f42b = { a7 44 [2] 83 4a [2] a8 66 [2] 86 44 [2] 92 5f [2] 9d 45 [2] 83 58 [2] 81 59 [2] 9a 5f [2] 86 58 [2] 9a 77 }

  condition:
    any of them
}