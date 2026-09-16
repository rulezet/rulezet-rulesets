rule TTP_XOR_QUAD_CurrentVersionRun_8540 {
  strings:
    $key_8540 = { d6 2f [2] f2 21 [2] d9 0d [2] f7 2f [2] e3 34 [2] ec 2e [2] f2 33 [2] f0 32 [2] eb 34 [2] f7 33 [2] eb 1c }

  condition:
    any of them
}