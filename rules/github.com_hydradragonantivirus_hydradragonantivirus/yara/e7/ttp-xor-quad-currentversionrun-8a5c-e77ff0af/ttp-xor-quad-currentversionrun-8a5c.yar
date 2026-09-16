rule TTP_XOR_QUAD_CurrentVersionRun_8a5c {
  strings:
    $key_8a5c = { d9 33 [2] fd 3d [2] d6 11 [2] f8 33 [2] ec 28 [2] e3 32 [2] fd 2f [2] ff 2e [2] e4 28 [2] f8 2f [2] e4 00 }

  condition:
    any of them
}