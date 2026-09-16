rule TTP_XOR_QUAD_CurrentVersionRun_81fa {
  strings:
    $key_81fa = { d2 95 [2] f6 9b [2] dd b7 [2] f3 95 [2] e7 8e [2] e8 94 [2] f6 89 [2] f4 88 [2] ef 8e [2] f3 89 [2] ef a6 }

  condition:
    any of them
}