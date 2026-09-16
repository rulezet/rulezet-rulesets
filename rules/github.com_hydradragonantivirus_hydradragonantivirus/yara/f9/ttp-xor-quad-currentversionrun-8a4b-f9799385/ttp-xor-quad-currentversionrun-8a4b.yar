rule TTP_XOR_QUAD_CurrentVersionRun_8a4b {
  strings:
    $key_8a4b = { d9 24 [2] fd 2a [2] d6 06 [2] f8 24 [2] ec 3f [2] e3 25 [2] fd 38 [2] ff 39 [2] e4 3f [2] f8 38 [2] e4 17 }

  condition:
    any of them
}