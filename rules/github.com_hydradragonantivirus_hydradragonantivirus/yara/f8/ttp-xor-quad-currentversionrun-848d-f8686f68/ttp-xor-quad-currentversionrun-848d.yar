rule TTP_XOR_QUAD_CurrentVersionRun_848d {
  strings:
    $key_848d = { d7 e2 [2] f3 ec [2] d8 c0 [2] f6 e2 [2] e2 f9 [2] ed e3 [2] f3 fe [2] f1 ff [2] ea f9 [2] f6 fe [2] ea d1 }

  condition:
    any of them
}