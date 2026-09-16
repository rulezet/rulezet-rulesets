rule TTP_XOR_QUAD_CurrentVersionRun_827d {
  strings:
    $key_827d = { d1 12 [2] f5 1c [2] de 30 [2] f0 12 [2] e4 09 [2] eb 13 [2] f5 0e [2] f7 0f [2] ec 09 [2] f0 0e [2] ec 21 }

  condition:
    any of them
}