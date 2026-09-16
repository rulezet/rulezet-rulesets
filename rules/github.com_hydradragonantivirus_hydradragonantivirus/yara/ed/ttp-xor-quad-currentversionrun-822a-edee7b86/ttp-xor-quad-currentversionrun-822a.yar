rule TTP_XOR_QUAD_CurrentVersionRun_822a {
  strings:
    $key_822a = { d1 45 [2] f5 4b [2] de 67 [2] f0 45 [2] e4 5e [2] eb 44 [2] f5 59 [2] f7 58 [2] ec 5e [2] f0 59 [2] ec 76 }

  condition:
    any of them
}