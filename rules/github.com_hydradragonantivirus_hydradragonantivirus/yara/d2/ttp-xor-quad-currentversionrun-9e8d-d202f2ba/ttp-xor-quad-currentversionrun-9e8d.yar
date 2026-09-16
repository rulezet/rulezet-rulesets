rule TTP_XOR_QUAD_CurrentVersionRun_9e8d {
  strings:
    $key_9e8d = { cd e2 [2] e9 ec [2] c2 c0 [2] ec e2 [2] f8 f9 [2] f7 e3 [2] e9 fe [2] eb ff [2] f0 f9 [2] ec fe [2] f0 d1 }

  condition:
    any of them
}