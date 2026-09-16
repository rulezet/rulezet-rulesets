rule TTP_XOR_QUAD_CurrentVersionRun_841d {
  strings:
    $key_841d = { d7 72 [2] f3 7c [2] d8 50 [2] f6 72 [2] e2 69 [2] ed 73 [2] f3 6e [2] f1 6f [2] ea 69 [2] f6 6e [2] ea 41 }

  condition:
    any of them
}