rule TTP_XOR_QUAD_CurrentVersionRun_84f6 {
  strings:
    $key_84f6 = { d7 99 [2] f3 97 [2] d8 bb [2] f6 99 [2] e2 82 [2] ed 98 [2] f3 85 [2] f1 84 [2] ea 82 [2] f6 85 [2] ea aa }

  condition:
    any of them
}