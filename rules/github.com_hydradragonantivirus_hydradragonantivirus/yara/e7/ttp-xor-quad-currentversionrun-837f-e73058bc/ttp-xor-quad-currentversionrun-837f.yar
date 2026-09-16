rule TTP_XOR_QUAD_CurrentVersionRun_837f {
  strings:
    $key_837f = { d0 10 [2] f4 1e [2] df 32 [2] f1 10 [2] e5 0b [2] ea 11 [2] f4 0c [2] f6 0d [2] ed 0b [2] f1 0c [2] ed 23 }

  condition:
    any of them
}