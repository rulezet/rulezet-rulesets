rule TTP_XOR_QUAD_CurrentVersionRun_831f {
  strings:
    $key_831f = { d0 70 [2] f4 7e [2] df 52 [2] f1 70 [2] e5 6b [2] ea 71 [2] f4 6c [2] f6 6d [2] ed 6b [2] f1 6c [2] ed 43 }

  condition:
    any of them
}