rule TTP_XOR_QUAD_CurrentVersionRun_94c1 {
  strings:
    $key_94c1 = { c7 ae [2] e3 a0 [2] c8 8c [2] e6 ae [2] f2 b5 [2] fd af [2] e3 b2 [2] e1 b3 [2] fa b5 [2] e6 b2 [2] fa 9d }

  condition:
    any of them
}