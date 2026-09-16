rule TTP_XOR_QUAD_CurrentVersionRun_94d1 {
  strings:
    $key_94d1 = { c7 be [2] e3 b0 [2] c8 9c [2] e6 be [2] f2 a5 [2] fd bf [2] e3 a2 [2] e1 a3 [2] fa a5 [2] e6 a2 [2] fa 8d }

  condition:
    any of them
}