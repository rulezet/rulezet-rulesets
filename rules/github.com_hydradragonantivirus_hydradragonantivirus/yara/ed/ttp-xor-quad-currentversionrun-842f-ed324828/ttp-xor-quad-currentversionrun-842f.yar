rule TTP_XOR_QUAD_CurrentVersionRun_842f {
  strings:
    $key_842f = { d7 40 [2] f3 4e [2] d8 62 [2] f6 40 [2] e2 5b [2] ed 41 [2] f3 5c [2] f1 5d [2] ea 5b [2] f6 5c [2] ea 73 }

  condition:
    any of them
}