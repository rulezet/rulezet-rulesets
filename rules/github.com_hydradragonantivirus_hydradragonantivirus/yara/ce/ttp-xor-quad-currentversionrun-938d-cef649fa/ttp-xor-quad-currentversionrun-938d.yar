rule TTP_XOR_QUAD_CurrentVersionRun_938d {
  strings:
    $key_938d = { c0 e2 [2] e4 ec [2] cf c0 [2] e1 e2 [2] f5 f9 [2] fa e3 [2] e4 fe [2] e6 ff [2] fd f9 [2] e1 fe [2] fd d1 }

  condition:
    any of them
}