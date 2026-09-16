rule TTP_XOR_QUAD_CurrentVersionRun_9b8d {
  strings:
    $key_9b8d = { c8 e2 [2] ec ec [2] c7 c0 [2] e9 e2 [2] fd f9 [2] f2 e3 [2] ec fe [2] ee ff [2] f5 f9 [2] e9 fe [2] f5 d1 }

  condition:
    any of them
}