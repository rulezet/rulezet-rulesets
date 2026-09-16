rule TTP_XOR_QUAD_CurrentVersionRun_8390 {
  strings:
    $key_8390 = { d0 ff [2] f4 f1 [2] df dd [2] f1 ff [2] e5 e4 [2] ea fe [2] f4 e3 [2] f6 e2 [2] ed e4 [2] f1 e3 [2] ed cc }

  condition:
    any of them
}