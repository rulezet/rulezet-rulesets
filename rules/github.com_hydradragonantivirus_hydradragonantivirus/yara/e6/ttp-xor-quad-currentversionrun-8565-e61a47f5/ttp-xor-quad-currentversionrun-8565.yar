rule TTP_XOR_QUAD_CurrentVersionRun_8565 {
  strings:
    $key_8565 = { d6 0a [2] f2 04 [2] d9 28 [2] f7 0a [2] e3 11 [2] ec 0b [2] f2 16 [2] f0 17 [2] eb 11 [2] f7 16 [2] eb 39 }

  condition:
    any of them
}