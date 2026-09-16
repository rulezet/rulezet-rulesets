rule TTP_XOR_QUAD_CurrentVersionRun_837a {
  strings:
    $key_837a = { d0 15 [2] f4 1b [2] df 37 [2] f1 15 [2] e5 0e [2] ea 14 [2] f4 09 [2] f6 08 [2] ed 0e [2] f1 09 [2] ed 26 }

  condition:
    any of them
}