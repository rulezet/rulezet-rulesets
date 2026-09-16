rule TTP_XOR_QUAD_CurrentVersionRun_8a75 {
  strings:
    $key_8a75 = { d9 1a [2] fd 14 [2] d6 38 [2] f8 1a [2] ec 01 [2] e3 1b [2] fd 06 [2] ff 07 [2] e4 01 [2] f8 06 [2] e4 29 }

  condition:
    any of them
}