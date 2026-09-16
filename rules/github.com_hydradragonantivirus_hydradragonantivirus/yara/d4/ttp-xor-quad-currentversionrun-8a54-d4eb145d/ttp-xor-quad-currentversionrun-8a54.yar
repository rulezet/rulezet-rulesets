rule TTP_XOR_QUAD_CurrentVersionRun_8a54 {
  strings:
    $key_8a54 = { d9 3b [2] fd 35 [2] d6 19 [2] f8 3b [2] ec 20 [2] e3 3a [2] fd 27 [2] ff 26 [2] e4 20 [2] f8 27 [2] e4 08 }

  condition:
    any of them
}