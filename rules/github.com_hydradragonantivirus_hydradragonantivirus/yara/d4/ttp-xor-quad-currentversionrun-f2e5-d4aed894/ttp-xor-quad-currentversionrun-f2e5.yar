rule TTP_XOR_QUAD_CurrentVersionRun_f2e5 {
  strings:
    $key_f2e5 = { a1 8a [2] 85 84 [2] ae a8 [2] 80 8a [2] 94 91 [2] 9b 8b [2] 85 96 [2] 87 97 [2] 9c 91 [2] 80 96 [2] 9c b9 }

  condition:
    any of them
}