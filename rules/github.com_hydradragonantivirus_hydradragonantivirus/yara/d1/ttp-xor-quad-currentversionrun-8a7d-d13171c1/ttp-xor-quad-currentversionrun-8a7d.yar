rule TTP_XOR_QUAD_CurrentVersionRun_8a7d {
  strings:
    $key_8a7d = { d9 12 [2] fd 1c [2] d6 30 [2] f8 12 [2] ec 09 [2] e3 13 [2] fd 0e [2] ff 0f [2] e4 09 [2] f8 0e [2] e4 21 }

  condition:
    any of them
}