rule TTP_XOR_QUAD_CurrentVersionRun_9f8c {
  strings:
    $key_9f8c = { cc e3 [2] e8 ed [2] c3 c1 [2] ed e3 [2] f9 f8 [2] f6 e2 [2] e8 ff [2] ea fe [2] f1 f8 [2] ed ff [2] f1 d0 }

  condition:
    any of them
}