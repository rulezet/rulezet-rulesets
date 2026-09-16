rule TTP_XOR_QUAD_CurrentVersionRun_8533 {
  strings:
    $key_8533 = { d6 5c [2] f2 52 [2] d9 7e [2] f7 5c [2] e3 47 [2] ec 5d [2] f2 40 [2] f0 41 [2] eb 47 [2] f7 40 [2] eb 6f }

  condition:
    any of them
}