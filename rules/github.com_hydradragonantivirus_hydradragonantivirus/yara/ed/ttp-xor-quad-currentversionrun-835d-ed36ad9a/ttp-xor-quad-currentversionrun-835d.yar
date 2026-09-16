rule TTP_XOR_QUAD_CurrentVersionRun_835d {
  strings:
    $key_835d = { d0 32 [2] f4 3c [2] df 10 [2] f1 32 [2] e5 29 [2] ea 33 [2] f4 2e [2] f6 2f [2] ed 29 [2] f1 2e [2] ed 01 }

  condition:
    any of them
}