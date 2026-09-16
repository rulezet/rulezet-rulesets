rule TTP_XOR_QUAD_CurrentVersionRun_844a {
  strings:
    $key_844a = { d7 25 [2] f3 2b [2] d8 07 [2] f6 25 [2] e2 3e [2] ed 24 [2] f3 39 [2] f1 38 [2] ea 3e [2] f6 39 [2] ea 16 }

  condition:
    any of them
}