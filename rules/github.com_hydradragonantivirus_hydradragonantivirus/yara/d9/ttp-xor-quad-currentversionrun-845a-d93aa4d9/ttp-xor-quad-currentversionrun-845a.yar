rule TTP_XOR_QUAD_CurrentVersionRun_845a {
  strings:
    $key_845a = { d7 35 [2] f3 3b [2] d8 17 [2] f6 35 [2] e2 2e [2] ed 34 [2] f3 29 [2] f1 28 [2] ea 2e [2] f6 29 [2] ea 06 }

  condition:
    any of them
}