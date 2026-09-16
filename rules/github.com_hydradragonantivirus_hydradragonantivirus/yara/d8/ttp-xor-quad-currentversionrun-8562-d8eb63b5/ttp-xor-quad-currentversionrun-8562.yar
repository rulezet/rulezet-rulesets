rule TTP_XOR_QUAD_CurrentVersionRun_8562 {
  strings:
    $key_8562 = { d6 0d [2] f2 03 [2] d9 2f [2] f7 0d [2] e3 16 [2] ec 0c [2] f2 11 [2] f0 10 [2] eb 16 [2] f7 11 [2] eb 3e }

  condition:
    any of them
}