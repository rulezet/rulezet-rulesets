rule TTP_XOR_QUAD_CurrentVersionRun_856e {
  strings:
    $key_856e = { d6 01 [2] f2 0f [2] d9 23 [2] f7 01 [2] e3 1a [2] ec 00 [2] f2 1d [2] f0 1c [2] eb 1a [2] f7 1d [2] eb 32 }

  condition:
    any of them
}