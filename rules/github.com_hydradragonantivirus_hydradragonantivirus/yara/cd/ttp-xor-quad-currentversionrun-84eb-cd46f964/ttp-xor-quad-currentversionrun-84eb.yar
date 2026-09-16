rule TTP_XOR_QUAD_CurrentVersionRun_84eb {
  strings:
    $key_84eb = { d7 84 [2] f3 8a [2] d8 a6 [2] f6 84 [2] e2 9f [2] ed 85 [2] f3 98 [2] f1 99 [2] ea 9f [2] f6 98 [2] ea b7 }

  condition:
    any of them
}