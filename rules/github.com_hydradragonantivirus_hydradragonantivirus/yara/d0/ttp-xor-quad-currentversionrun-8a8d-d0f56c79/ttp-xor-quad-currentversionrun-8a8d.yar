rule TTP_XOR_QUAD_CurrentVersionRun_8a8d {
  strings:
    $key_8a8d = { d9 e2 [2] fd ec [2] d6 c0 [2] f8 e2 [2] ec f9 [2] e3 e3 [2] fd fe [2] ff ff [2] e4 f9 [2] f8 fe [2] e4 d1 }

  condition:
    any of them
}