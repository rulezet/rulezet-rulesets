rule TTP_XOR_QUAD_CurrentVersionRun_f244 {
  strings:
    $key_f244 = { a1 2b [2] 85 25 [2] ae 09 [2] 80 2b [2] 94 30 [2] 9b 2a [2] 85 37 [2] 87 36 [2] 9c 30 [2] 80 37 [2] 9c 18 }

  condition:
    any of them
}