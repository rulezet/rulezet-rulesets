rule TTP_XOR_QUAD_CurrentVersionRun_4e8c {
  strings:
    $key_4e8c = { 1d e3 [2] 39 ed [2] 12 c1 [2] 3c e3 [2] 28 f8 [2] 27 e2 [2] 39 ff [2] 3b fe [2] 20 f8 [2] 3c ff [2] 20 d0 }

  condition:
    any of them
}