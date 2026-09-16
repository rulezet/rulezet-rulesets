rule TTP_XOR_QUAD_CurrentVersionRun_bc91 {
  strings:
    $key_bc91 = { ef fe [2] cb f0 [2] e0 dc [2] ce fe [2] da e5 [2] d5 ff [2] cb e2 [2] c9 e3 [2] d2 e5 [2] ce e2 [2] d2 cd }

  condition:
    any of them
}