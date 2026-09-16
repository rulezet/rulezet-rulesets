rule TTP_XOR_QUAD_CurrentVersionRun_855f {
  strings:
    $key_855f = { d6 30 [2] f2 3e [2] d9 12 [2] f7 30 [2] e3 2b [2] ec 31 [2] f2 2c [2] f0 2d [2] eb 2b [2] f7 2c [2] eb 03 }

  condition:
    any of them
}