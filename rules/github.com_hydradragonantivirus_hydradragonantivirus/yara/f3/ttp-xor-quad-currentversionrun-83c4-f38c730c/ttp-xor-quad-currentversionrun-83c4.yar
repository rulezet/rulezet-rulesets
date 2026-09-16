rule TTP_XOR_QUAD_CurrentVersionRun_83c4 {
  strings:
    $key_83c4 = { d0 ab [2] f4 a5 [2] df 89 [2] f1 ab [2] e5 b0 [2] ea aa [2] f4 b7 [2] f6 b6 [2] ed b0 [2] f1 b7 [2] ed 98 }

  condition:
    any of them
}