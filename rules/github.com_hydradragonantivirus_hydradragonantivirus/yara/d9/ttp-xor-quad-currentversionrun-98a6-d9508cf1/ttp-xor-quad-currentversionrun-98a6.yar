rule TTP_XOR_QUAD_CurrentVersionRun_98a6 {
  strings:
    $key_98a6 = { cb c9 [2] ef c7 [2] c4 eb [2] ea c9 [2] fe d2 [2] f1 c8 [2] ef d5 [2] ed d4 [2] f6 d2 [2] ea d5 [2] f6 fa }

  condition:
    any of them
}