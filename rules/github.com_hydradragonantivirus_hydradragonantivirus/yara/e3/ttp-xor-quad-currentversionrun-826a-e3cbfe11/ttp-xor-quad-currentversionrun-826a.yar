rule TTP_XOR_QUAD_CurrentVersionRun_826a {
  strings:
    $key_826a = { d1 05 [2] f5 0b [2] de 27 [2] f0 05 [2] e4 1e [2] eb 04 [2] f5 19 [2] f7 18 [2] ec 1e [2] f0 19 [2] ec 36 }

  condition:
    any of them
}