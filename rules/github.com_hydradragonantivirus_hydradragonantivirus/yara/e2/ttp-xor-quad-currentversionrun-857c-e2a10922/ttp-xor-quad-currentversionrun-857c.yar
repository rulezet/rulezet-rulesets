rule TTP_XOR_QUAD_CurrentVersionRun_857c {
  strings:
    $key_857c = { d6 13 [2] f2 1d [2] d9 31 [2] f7 13 [2] e3 08 [2] ec 12 [2] f2 0f [2] f0 0e [2] eb 08 [2] f7 0f [2] eb 20 }

  condition:
    any of them
}