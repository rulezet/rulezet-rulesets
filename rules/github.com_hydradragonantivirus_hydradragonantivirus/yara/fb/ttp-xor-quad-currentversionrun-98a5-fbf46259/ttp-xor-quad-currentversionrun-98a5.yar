rule TTP_XOR_QUAD_CurrentVersionRun_98a5 {
  strings:
    $key_98a5 = { cb ca [2] ef c4 [2] c4 e8 [2] ea ca [2] fe d1 [2] f1 cb [2] ef d6 [2] ed d7 [2] f6 d1 [2] ea d6 [2] f6 f9 }

  condition:
    any of them
}