rule TTP_XOR_QUAD_CurrentVersionRun_8a6d {
  strings:
    $key_8a6d = { d9 02 [2] fd 0c [2] d6 20 [2] f8 02 [2] ec 19 [2] e3 03 [2] fd 1e [2] ff 1f [2] e4 19 [2] f8 1e [2] e4 31 }

  condition:
    any of them
}