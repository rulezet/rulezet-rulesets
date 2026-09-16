rule TTP_XOR_QUAD_CurrentVersionRun_9a93 {
  strings:
    $key_9a93 = { c9 fc [2] ed f2 [2] c6 de [2] e8 fc [2] fc e7 [2] f3 fd [2] ed e0 [2] ef e1 [2] f4 e7 [2] e8 e0 [2] f4 cf }

  condition:
    any of them
}