rule TTP_XOR_QUAD_CurrentVersionRun_8537 {
  strings:
    $key_8537 = { d6 58 [2] f2 56 [2] d9 7a [2] f7 58 [2] e3 43 [2] ec 59 [2] f2 44 [2] f0 45 [2] eb 43 [2] f7 44 [2] eb 6b }

  condition:
    any of them
}