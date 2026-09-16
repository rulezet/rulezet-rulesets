rule TTP_XOR_QUAD_CurrentVersionRun_844f {
  strings:
    $key_844f = { d7 20 [2] f3 2e [2] d8 02 [2] f6 20 [2] e2 3b [2] ed 21 [2] f3 3c [2] f1 3d [2] ea 3b [2] f6 3c [2] ea 13 }

  condition:
    any of them
}