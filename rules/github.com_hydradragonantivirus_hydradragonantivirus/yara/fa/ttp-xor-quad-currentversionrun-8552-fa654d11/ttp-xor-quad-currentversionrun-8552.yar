rule TTP_XOR_QUAD_CurrentVersionRun_8552 {
  strings:
    $key_8552 = { d6 3d [2] f2 33 [2] d9 1f [2] f7 3d [2] e3 26 [2] ec 3c [2] f2 21 [2] f0 20 [2] eb 26 [2] f7 21 [2] eb 0e }

  condition:
    any of them
}