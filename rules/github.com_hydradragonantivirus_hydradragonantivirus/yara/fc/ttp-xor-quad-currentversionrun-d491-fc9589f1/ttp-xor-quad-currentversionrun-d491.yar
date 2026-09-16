rule TTP_XOR_QUAD_CurrentVersionRun_d491 {
  strings:
    $key_d491 = { 87 fe [2] a3 f0 [2] 88 dc [2] a6 fe [2] b2 e5 [2] bd ff [2] a3 e2 [2] a1 e3 [2] ba e5 [2] a6 e2 [2] ba cd }

  condition:
    any of them
}