rule TTP_XOR_QUAD_CurrentVersionRun_8a7f {
  strings:
    $key_8a7f = { d9 10 [2] fd 1e [2] d6 32 [2] f8 10 [2] ec 0b [2] e3 11 [2] fd 0c [2] ff 0d [2] e4 0b [2] f8 0c [2] e4 23 }

  condition:
    any of them
}