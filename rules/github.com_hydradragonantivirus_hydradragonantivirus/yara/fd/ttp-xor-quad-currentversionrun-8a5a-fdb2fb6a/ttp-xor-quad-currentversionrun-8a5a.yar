rule TTP_XOR_QUAD_CurrentVersionRun_8a5a {
  strings:
    $key_8a5a = { d9 35 [2] fd 3b [2] d6 17 [2] f8 35 [2] ec 2e [2] e3 34 [2] fd 29 [2] ff 28 [2] e4 2e [2] f8 29 [2] e4 06 }

  condition:
    any of them
}