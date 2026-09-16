rule TTP_XOR_QUAD_CurrentVersionRun_8551 {
  strings:
    $key_8551 = { d6 3e [2] f2 30 [2] d9 1c [2] f7 3e [2] e3 25 [2] ec 3f [2] f2 22 [2] f0 23 [2] eb 25 [2] f7 22 [2] eb 0d }

  condition:
    any of them
}