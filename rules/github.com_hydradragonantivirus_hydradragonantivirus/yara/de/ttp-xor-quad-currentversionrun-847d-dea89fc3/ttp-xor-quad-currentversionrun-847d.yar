rule TTP_XOR_QUAD_CurrentVersionRun_847d {
  strings:
    $key_847d = { d7 12 [2] f3 1c [2] d8 30 [2] f6 12 [2] e2 09 [2] ed 13 [2] f3 0e [2] f1 0f [2] ea 09 [2] f6 0e [2] ea 21 }

  condition:
    any of them
}