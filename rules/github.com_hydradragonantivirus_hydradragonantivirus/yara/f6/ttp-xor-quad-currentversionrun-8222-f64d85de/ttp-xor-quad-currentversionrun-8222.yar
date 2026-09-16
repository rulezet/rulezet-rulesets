rule TTP_XOR_QUAD_CurrentVersionRun_8222 {
  strings:
    $key_8222 = { d1 4d [2] f5 43 [2] de 6f [2] f0 4d [2] e4 56 [2] eb 4c [2] f5 51 [2] f7 50 [2] ec 56 [2] f0 51 [2] ec 7e }

  condition:
    any of them
}