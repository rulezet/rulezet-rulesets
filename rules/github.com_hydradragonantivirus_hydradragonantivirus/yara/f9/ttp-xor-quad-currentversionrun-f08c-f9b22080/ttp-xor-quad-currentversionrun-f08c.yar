rule TTP_XOR_QUAD_CurrentVersionRun_f08c {
  strings:
    $key_f08c = { a3 e3 [2] 87 ed [2] ac c1 [2] 82 e3 [2] 96 f8 [2] 99 e2 [2] 87 ff [2] 85 fe [2] 9e f8 [2] 82 ff [2] 9e d0 }

  condition:
    any of them
}