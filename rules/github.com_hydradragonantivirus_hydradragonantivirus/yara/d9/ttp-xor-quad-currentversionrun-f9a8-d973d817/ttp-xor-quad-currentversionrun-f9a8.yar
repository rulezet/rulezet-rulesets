rule TTP_XOR_QUAD_CurrentVersionRun_f9a8 {
  strings:
    $key_f9a8 = { aa c7 [2] 8e c9 [2] a5 e5 [2] 8b c7 [2] 9f dc [2] 90 c6 [2] 8e db [2] 8c da [2] 97 dc [2] 8b db [2] 97 f4 }

  condition:
    any of them
}