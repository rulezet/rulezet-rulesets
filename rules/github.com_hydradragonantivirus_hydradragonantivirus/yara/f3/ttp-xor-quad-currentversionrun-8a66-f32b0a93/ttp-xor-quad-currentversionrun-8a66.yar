rule TTP_XOR_QUAD_CurrentVersionRun_8a66 {
  strings:
    $key_8a66 = { d9 09 [2] fd 07 [2] d6 2b [2] f8 09 [2] ec 12 [2] e3 08 [2] fd 15 [2] ff 14 [2] e4 12 [2] f8 15 [2] e4 3a }

  condition:
    any of them
}