rule TTP_XOR_QUAD_CurrentVersionRun_8201 {
  strings:
    $key_8201 = { d1 6e [2] f5 60 [2] de 4c [2] f0 6e [2] e4 75 [2] eb 6f [2] f5 72 [2] f7 73 [2] ec 75 [2] f0 72 [2] ec 5d }

  condition:
    any of them
}