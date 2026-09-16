rule TTP_XOR_QUAD_CurrentVersionRun_8271 {
  strings:
    $key_8271 = { d1 1e [2] f5 10 [2] de 3c [2] f0 1e [2] e4 05 [2] eb 1f [2] f5 02 [2] f7 03 [2] ec 05 [2] f0 02 [2] ec 2d }

  condition:
    any of them
}