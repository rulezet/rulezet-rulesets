rule TTP_XOR_QUAD_CurrentVersionRun_fa8c {
  strings:
    $key_fa8c = { a9 e3 [2] 8d ed [2] a6 c1 [2] 88 e3 [2] 9c f8 [2] 93 e2 [2] 8d ff [2] 8f fe [2] 94 f8 [2] 88 ff [2] 94 d0 }

  condition:
    any of them
}