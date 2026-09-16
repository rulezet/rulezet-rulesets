rule TTP_XOR_QUAD_CurrentVersionRun_2e8c {
  strings:
    $key_2e8c = { 7d e3 [2] 59 ed [2] 72 c1 [2] 5c e3 [2] 48 f8 [2] 47 e2 [2] 59 ff [2] 5b fe [2] 40 f8 [2] 5c ff [2] 40 d0 }

  condition:
    any of them
}