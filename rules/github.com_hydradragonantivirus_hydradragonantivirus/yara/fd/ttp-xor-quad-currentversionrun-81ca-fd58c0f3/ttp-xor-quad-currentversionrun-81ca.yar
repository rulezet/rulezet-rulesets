rule TTP_XOR_QUAD_CurrentVersionRun_81ca {
  strings:
    $key_81ca = { d2 a5 [2] f6 ab [2] dd 87 [2] f3 a5 [2] e7 be [2] e8 a4 [2] f6 b9 [2] f4 b8 [2] ef be [2] f3 b9 [2] ef 96 }

  condition:
    any of them
}