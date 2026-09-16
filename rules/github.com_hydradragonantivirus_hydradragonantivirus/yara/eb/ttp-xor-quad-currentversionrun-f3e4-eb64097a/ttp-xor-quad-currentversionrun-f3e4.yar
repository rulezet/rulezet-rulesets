rule TTP_XOR_QUAD_CurrentVersionRun_f3e4 {
  strings:
    $key_f3e4 = { a0 8b [2] 84 85 [2] af a9 [2] 81 8b [2] 95 90 [2] 9a 8a [2] 84 97 [2] 86 96 [2] 9d 90 [2] 81 97 [2] 9d b8 }

  condition:
    any of them
}