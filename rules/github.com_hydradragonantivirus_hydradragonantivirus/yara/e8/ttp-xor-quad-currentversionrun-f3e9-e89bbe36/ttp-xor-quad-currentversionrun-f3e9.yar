rule TTP_XOR_QUAD_CurrentVersionRun_f3e9 {
  strings:
    $key_f3e9 = { a0 86 [2] 84 88 [2] af a4 [2] 81 86 [2] 95 9d [2] 9a 87 [2] 84 9a [2] 86 9b [2] 9d 9d [2] 81 9a [2] 9d b5 }

  condition:
    any of them
}