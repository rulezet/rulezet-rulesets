rule TTP_XOR_QUAD_CurrentVersionRun_87d7 {
  strings:
    $key_87d7 = { d4 b8 [2] f0 b6 [2] db 9a [2] f5 b8 [2] e1 a3 [2] ee b9 [2] f0 a4 [2] f2 a5 [2] e9 a3 [2] f5 a4 [2] e9 8b }

  condition:
    any of them
}