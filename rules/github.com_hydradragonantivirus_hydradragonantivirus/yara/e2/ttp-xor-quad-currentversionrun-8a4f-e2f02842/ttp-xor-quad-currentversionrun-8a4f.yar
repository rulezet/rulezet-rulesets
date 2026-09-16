rule TTP_XOR_QUAD_CurrentVersionRun_8a4f {
  strings:
    $key_8a4f = { d9 20 [2] fd 2e [2] d6 02 [2] f8 20 [2] ec 3b [2] e3 21 [2] fd 3c [2] ff 3d [2] e4 3b [2] f8 3c [2] e4 13 }

  condition:
    any of them
}