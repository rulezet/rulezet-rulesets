rule TTP_XOR_QUAD_CurrentVersionRun_f7a6 {
  strings:
    $key_f7a6 = { a4 c9 [2] 80 c7 [2] ab eb [2] 85 c9 [2] 91 d2 [2] 9e c8 [2] 80 d5 [2] 82 d4 [2] 99 d2 [2] 85 d5 [2] 99 fa }

  condition:
    any of them
}