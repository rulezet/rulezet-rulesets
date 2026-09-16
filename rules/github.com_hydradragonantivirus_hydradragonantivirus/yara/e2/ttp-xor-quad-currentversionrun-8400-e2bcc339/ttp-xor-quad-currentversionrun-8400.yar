rule TTP_XOR_QUAD_CurrentVersionRun_8400 {
  strings:
    $key_8400 = { d7 6f [2] f3 61 [2] d8 4d [2] f6 6f [2] e2 74 [2] ed 6e [2] f3 73 [2] f1 72 [2] ea 74 [2] f6 73 [2] ea 5c }

  condition:
    any of them
}