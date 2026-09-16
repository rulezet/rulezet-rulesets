rule TTP_XOR_QUAD_CurrentVersionRun_8a55 {
  strings:
    $key_8a55 = { d9 3a [2] fd 34 [2] d6 18 [2] f8 3a [2] ec 21 [2] e3 3b [2] fd 26 [2] ff 27 [2] e4 21 [2] f8 26 [2] e4 09 }

  condition:
    any of them
}