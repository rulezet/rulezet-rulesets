rule TTP_XOR_QUAD_CurrentVersionRun_9a8c {
  strings:
    $key_9a8c = { c9 e3 [2] ed ed [2] c6 c1 [2] e8 e3 [2] fc f8 [2] f3 e2 [2] ed ff [2] ef fe [2] f4 f8 [2] e8 ff [2] f4 d0 }

  condition:
    any of them
}