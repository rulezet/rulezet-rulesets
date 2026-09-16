rule TTP_XOR_QUAD_CurrentVersionRun_855c {
  strings:
    $key_855c = { d6 33 [2] f2 3d [2] d9 11 [2] f7 33 [2] e3 28 [2] ec 32 [2] f2 2f [2] f0 2e [2] eb 28 [2] f7 2f [2] eb 00 }

  condition:
    any of them
}