rule TTP_XOR_QUAD_CurrentVersionRun_0587 {
  strings:
    $key_0587 = { 56 e8 [2] 72 e6 [2] 59 ca [2] 77 e8 [2] 63 f3 [2] 6c e9 [2] 72 f4 [2] 70 f5 [2] 6b f3 [2] 77 f4 [2] 6b db }

  condition:
    any of them
}