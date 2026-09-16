rule TTP_XOR_QUAD_CurrentVersionRun_94f3 {
  strings:
    $key_94f3 = { c7 9c [2] e3 92 [2] c8 be [2] e6 9c [2] f2 87 [2] fd 9d [2] e3 80 [2] e1 81 [2] fa 87 [2] e6 80 [2] fa af }

  condition:
    any of them
}