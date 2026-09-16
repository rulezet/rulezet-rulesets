rule TTP_XOR_QUAD_CurrentVersionRun_8523 {
  strings:
    $key_8523 = { d6 4c [2] f2 42 [2] d9 6e [2] f7 4c [2] e3 57 [2] ec 4d [2] f2 50 [2] f0 51 [2] eb 57 [2] f7 50 [2] eb 7f }

  condition:
    any of them
}