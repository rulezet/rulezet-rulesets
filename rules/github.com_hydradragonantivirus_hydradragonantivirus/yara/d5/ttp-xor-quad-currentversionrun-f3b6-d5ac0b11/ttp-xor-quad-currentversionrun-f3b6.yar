rule TTP_XOR_QUAD_CurrentVersionRun_f3b6 {
  strings:
    $key_f3b6 = { a0 d9 [2] 84 d7 [2] af fb [2] 81 d9 [2] 95 c2 [2] 9a d8 [2] 84 c5 [2] 86 c4 [2] 9d c2 [2] 81 c5 [2] 9d ea }

  condition:
    any of them
}