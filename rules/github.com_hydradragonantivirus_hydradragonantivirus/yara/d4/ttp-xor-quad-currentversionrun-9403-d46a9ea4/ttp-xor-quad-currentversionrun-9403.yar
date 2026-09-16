rule TTP_XOR_QUAD_CurrentVersionRun_9403 {
  strings:
    $key_9403 = { c7 6c [2] e3 62 [2] c8 4e [2] e6 6c [2] f2 77 [2] fd 6d [2] e3 70 [2] e1 71 [2] fa 77 [2] e6 70 [2] fa 5f }

  condition:
    any of them
}