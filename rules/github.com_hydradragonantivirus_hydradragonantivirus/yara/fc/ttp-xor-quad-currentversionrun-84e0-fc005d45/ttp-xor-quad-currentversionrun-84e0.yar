rule TTP_XOR_QUAD_CurrentVersionRun_84e0 {
  strings:
    $key_84e0 = { d7 8f [2] f3 81 [2] d8 ad [2] f6 8f [2] e2 94 [2] ed 8e [2] f3 93 [2] f1 92 [2] ea 94 [2] f6 93 [2] ea bc }

  condition:
    any of them
}