rule TTP_XOR_QUAD_CurrentVersionRun_83c1 {
  strings:
    $key_83c1 = { d0 ae [2] f4 a0 [2] df 8c [2] f1 ae [2] e5 b5 [2] ea af [2] f4 b2 [2] f6 b3 [2] ed b5 [2] f1 b2 [2] ed 9d }

  condition:
    any of them
}