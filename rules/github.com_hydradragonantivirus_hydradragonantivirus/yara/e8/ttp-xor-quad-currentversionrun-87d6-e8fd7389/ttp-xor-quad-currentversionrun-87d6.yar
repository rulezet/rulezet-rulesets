rule TTP_XOR_QUAD_CurrentVersionRun_87d6 {
  strings:
    $key_87d6 = { d4 b9 [2] f0 b7 [2] db 9b [2] f5 b9 [2] e1 a2 [2] ee b8 [2] f0 a5 [2] f2 a4 [2] e9 a2 [2] f5 a5 [2] e9 8a }

  condition:
    any of them
}