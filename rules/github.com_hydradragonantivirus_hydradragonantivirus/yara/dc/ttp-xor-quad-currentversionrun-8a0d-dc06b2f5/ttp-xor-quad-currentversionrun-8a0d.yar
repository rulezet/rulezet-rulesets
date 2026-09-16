rule TTP_XOR_QUAD_CurrentVersionRun_8a0d {
  strings:
    $key_8a0d = { d9 62 [2] fd 6c [2] d6 40 [2] f8 62 [2] ec 79 [2] e3 63 [2] fd 7e [2] ff 7f [2] e4 79 [2] f8 7e [2] e4 51 }

  condition:
    any of them
}