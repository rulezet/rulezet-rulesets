rule TTP_XOR_QUAD_CurrentVersionRun_8a3f {
  strings:
    $key_8a3f = { d9 50 [2] fd 5e [2] d6 72 [2] f8 50 [2] ec 4b [2] e3 51 [2] fd 4c [2] ff 4d [2] e4 4b [2] f8 4c [2] e4 63 }

  condition:
    any of them
}