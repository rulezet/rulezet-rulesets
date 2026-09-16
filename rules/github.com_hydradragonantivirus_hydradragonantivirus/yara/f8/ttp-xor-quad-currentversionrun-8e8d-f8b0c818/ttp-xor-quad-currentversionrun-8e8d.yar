rule TTP_XOR_QUAD_CurrentVersionRun_8e8d {
  strings:
    $key_8e8d = { dd e2 [2] f9 ec [2] d2 c0 [2] fc e2 [2] e8 f9 [2] e7 e3 [2] f9 fe [2] fb ff [2] e0 f9 [2] fc fe [2] e0 d1 }

  condition:
    any of them
}