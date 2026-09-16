rule TTP_XOR_QUAD_CurrentVersionRun_9a84 {
  strings:
    $key_9a84 = { c9 eb [2] ed e5 [2] c6 c9 [2] e8 eb [2] fc f0 [2] f3 ea [2] ed f7 [2] ef f6 [2] f4 f0 [2] e8 f7 [2] f4 d8 }

  condition:
    any of them
}