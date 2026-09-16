rule TTP_XOR_QUAD_CurrentVersionRun_e796 {
  strings:
    $key_e796 = { b4 f9 [2] 90 f7 [2] bb db [2] 95 f9 [2] 81 e2 [2] 8e f8 [2] 90 e5 [2] 92 e4 [2] 89 e2 [2] 95 e5 [2] 89 ca }

  condition:
    any of them
}