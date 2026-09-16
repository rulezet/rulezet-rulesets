rule TTP_XOR_QUAD_CurrentVersionRun_f58a {
  strings:
    $key_f58a = { a6 e5 [2] 82 eb [2] a9 c7 [2] 87 e5 [2] 93 fe [2] 9c e4 [2] 82 f9 [2] 80 f8 [2] 9b fe [2] 87 f9 [2] 9b d6 }

  condition:
    any of them
}