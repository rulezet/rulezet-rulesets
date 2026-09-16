rule TTP_XOR_QUAD_CurrentVersionRun_f6f4 {
  strings:
    $key_f6f4 = { a5 9b [2] 81 95 [2] aa b9 [2] 84 9b [2] 90 80 [2] 9f 9a [2] 81 87 [2] 83 86 [2] 98 80 [2] 84 87 [2] 98 a8 }

  condition:
    any of them
}