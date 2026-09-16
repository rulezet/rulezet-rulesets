rule TTP_XOR_QUAD_CurrentVersionRun_83ca {
  strings:
    $key_83ca = { d0 a5 [2] f4 ab [2] df 87 [2] f1 a5 [2] e5 be [2] ea a4 [2] f4 b9 [2] f6 b8 [2] ed be [2] f1 b9 [2] ed 96 }

  condition:
    any of them
}