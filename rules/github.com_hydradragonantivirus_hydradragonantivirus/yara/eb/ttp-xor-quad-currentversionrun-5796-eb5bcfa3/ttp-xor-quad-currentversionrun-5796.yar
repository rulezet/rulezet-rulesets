rule TTP_XOR_QUAD_CurrentVersionRun_5796 {
  strings:
    $key_5796 = { 04 f9 [2] 20 f7 [2] 0b db [2] 25 f9 [2] 31 e2 [2] 3e f8 [2] 20 e5 [2] 22 e4 [2] 39 e2 [2] 25 e5 [2] 39 ca }

  condition:
    any of them
}