rule TTP_XOR_QUAD_CurrentVersionRun_8a74 {
  strings:
    $key_8a74 = { d9 1b [2] fd 15 [2] d6 39 [2] f8 1b [2] ec 00 [2] e3 1a [2] fd 07 [2] ff 06 [2] e4 00 [2] f8 07 [2] e4 28 }

  condition:
    any of them
}