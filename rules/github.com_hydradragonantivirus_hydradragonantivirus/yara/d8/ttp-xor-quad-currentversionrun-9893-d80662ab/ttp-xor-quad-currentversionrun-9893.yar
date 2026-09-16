rule TTP_XOR_QUAD_CurrentVersionRun_9893 {
  strings:
    $key_9893 = { cb fc [2] ef f2 [2] c4 de [2] ea fc [2] fe e7 [2] f1 fd [2] ef e0 [2] ed e1 [2] f6 e7 [2] ea e0 [2] f6 cf }

  condition:
    any of them
}