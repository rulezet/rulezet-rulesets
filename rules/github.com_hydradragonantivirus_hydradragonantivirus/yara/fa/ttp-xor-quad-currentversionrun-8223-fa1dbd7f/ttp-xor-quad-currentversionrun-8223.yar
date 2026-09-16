rule TTP_XOR_QUAD_CurrentVersionRun_8223 {
  strings:
    $key_8223 = { d1 4c [2] f5 42 [2] de 6e [2] f0 4c [2] e4 57 [2] eb 4d [2] f5 50 [2] f7 51 [2] ec 57 [2] f0 50 [2] ec 7f }

  condition:
    any of them
}