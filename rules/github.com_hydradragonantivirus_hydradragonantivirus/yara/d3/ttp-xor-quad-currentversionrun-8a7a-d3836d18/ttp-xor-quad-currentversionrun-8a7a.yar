rule TTP_XOR_QUAD_CurrentVersionRun_8a7a {
  strings:
    $key_8a7a = { d9 15 [2] fd 1b [2] d6 37 [2] f8 15 [2] ec 0e [2] e3 14 [2] fd 09 [2] ff 08 [2] e4 0e [2] f8 09 [2] e4 26 }

  condition:
    any of them
}