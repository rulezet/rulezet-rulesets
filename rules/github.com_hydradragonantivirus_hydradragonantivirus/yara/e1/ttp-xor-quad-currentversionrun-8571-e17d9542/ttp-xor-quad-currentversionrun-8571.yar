rule TTP_XOR_QUAD_CurrentVersionRun_8571 {
  strings:
    $key_8571 = { d6 1e [2] f2 10 [2] d9 3c [2] f7 1e [2] e3 05 [2] ec 1f [2] f2 02 [2] f0 03 [2] eb 05 [2] f7 02 [2] eb 2d }

  condition:
    any of them
}