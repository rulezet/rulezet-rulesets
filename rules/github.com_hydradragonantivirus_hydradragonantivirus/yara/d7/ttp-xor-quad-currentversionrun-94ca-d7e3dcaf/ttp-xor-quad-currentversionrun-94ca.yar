rule TTP_XOR_QUAD_CurrentVersionRun_94ca {
  strings:
    $key_94ca = { c7 a5 [2] e3 ab [2] c8 87 [2] e6 a5 [2] f2 be [2] fd a4 [2] e3 b9 [2] e1 b8 [2] fa be [2] e6 b9 [2] fa 96 }

  condition:
    any of them
}