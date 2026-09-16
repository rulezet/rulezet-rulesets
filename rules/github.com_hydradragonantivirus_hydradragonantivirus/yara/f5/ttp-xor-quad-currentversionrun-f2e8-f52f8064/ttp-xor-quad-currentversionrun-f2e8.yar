rule TTP_XOR_QUAD_CurrentVersionRun_f2e8 {
  strings:
    $key_f2e8 = { a1 87 [2] 85 89 [2] ae a5 [2] 80 87 [2] 94 9c [2] 9b 86 [2] 85 9b [2] 87 9a [2] 9c 9c [2] 80 9b [2] 9c b4 }

  condition:
    any of them
}