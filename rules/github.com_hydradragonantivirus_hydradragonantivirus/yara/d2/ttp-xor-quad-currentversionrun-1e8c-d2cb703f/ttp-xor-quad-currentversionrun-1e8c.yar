rule TTP_XOR_QUAD_CurrentVersionRun_1e8c {
  strings:
    $key_1e8c = { 4d e3 [2] 69 ed [2] 42 c1 [2] 6c e3 [2] 78 f8 [2] 77 e2 [2] 69 ff [2] 6b fe [2] 70 f8 [2] 6c ff [2] 70 d0 }

  condition:
    any of them
}