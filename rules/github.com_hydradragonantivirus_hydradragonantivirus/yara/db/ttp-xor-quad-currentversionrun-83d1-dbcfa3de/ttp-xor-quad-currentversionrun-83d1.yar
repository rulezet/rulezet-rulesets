rule TTP_XOR_QUAD_CurrentVersionRun_83d1 {
  strings:
    $key_83d1 = { d0 be [2] f4 b0 [2] df 9c [2] f1 be [2] e5 a5 [2] ea bf [2] f4 a2 [2] f6 a3 [2] ed a5 [2] f1 a2 [2] ed 8d }

  condition:
    any of them
}