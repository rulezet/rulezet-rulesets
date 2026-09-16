rule TTP_XOR_QUAD_CurrentVersionRun_8a1d {
  strings:
    $key_8a1d = { d9 72 [2] fd 7c [2] d6 50 [2] f8 72 [2] ec 69 [2] e3 73 [2] fd 6e [2] ff 6f [2] e4 69 [2] f8 6e [2] e4 41 }

  condition:
    any of them
}