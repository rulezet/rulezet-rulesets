rule TTP_XOR_QUAD_CurrentVersionRun_8a59 {
  strings:
    $key_8a59 = { d9 36 [2] fd 38 [2] d6 14 [2] f8 36 [2] ec 2d [2] e3 37 [2] fd 2a [2] ff 2b [2] e4 2d [2] f8 2a [2] e4 05 }

  condition:
    any of them
}