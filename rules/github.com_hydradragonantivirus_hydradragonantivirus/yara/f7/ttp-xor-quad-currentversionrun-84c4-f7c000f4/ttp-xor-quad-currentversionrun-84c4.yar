rule TTP_XOR_QUAD_CurrentVersionRun_84c4 {
  strings:
    $key_84c4 = { d7 ab [2] f3 a5 [2] d8 89 [2] f6 ab [2] e2 b0 [2] ed aa [2] f3 b7 [2] f1 b6 [2] ea b0 [2] f6 b7 [2] ea 98 }

  condition:
    any of them
}