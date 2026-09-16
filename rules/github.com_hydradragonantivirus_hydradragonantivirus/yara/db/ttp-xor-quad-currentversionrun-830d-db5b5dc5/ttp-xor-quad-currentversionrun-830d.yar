rule TTP_XOR_QUAD_CurrentVersionRun_830d {
  strings:
    $key_830d = { d0 62 [2] f4 6c [2] df 40 [2] f1 62 [2] e5 79 [2] ea 63 [2] f4 7e [2] f6 7f [2] ed 79 [2] f1 7e [2] ed 51 }

  condition:
    any of them
}