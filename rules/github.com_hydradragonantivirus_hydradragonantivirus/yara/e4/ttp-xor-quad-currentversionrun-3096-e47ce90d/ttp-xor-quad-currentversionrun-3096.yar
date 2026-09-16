rule TTP_XOR_QUAD_CurrentVersionRun_3096 {
  strings:
    $key_3096 = { 63 f9 [2] 47 f7 [2] 6c db [2] 42 f9 [2] 56 e2 [2] 59 f8 [2] 47 e5 [2] 45 e4 [2] 5e e2 [2] 42 e5 [2] 5e ca }

  condition:
    any of them
}