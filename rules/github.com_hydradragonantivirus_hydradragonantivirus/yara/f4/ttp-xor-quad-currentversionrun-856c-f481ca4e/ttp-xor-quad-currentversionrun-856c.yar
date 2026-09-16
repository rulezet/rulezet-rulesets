rule TTP_XOR_QUAD_CurrentVersionRun_856c {
  strings:
    $key_856c = { d6 03 [2] f2 0d [2] d9 21 [2] f7 03 [2] e3 18 [2] ec 02 [2] f2 1f [2] f0 1e [2] eb 18 [2] f7 1f [2] eb 30 }

  condition:
    any of them
}