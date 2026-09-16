rule TTP_XOR_QUAD_CurrentVersionRun_8a4d {
  strings:
    $key_8a4d = { d9 22 [2] fd 2c [2] d6 00 [2] f8 22 [2] ec 39 [2] e3 23 [2] fd 3e [2] ff 3f [2] e4 39 [2] f8 3e [2] e4 11 }

  condition:
    any of them
}