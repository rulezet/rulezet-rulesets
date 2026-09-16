rule TTP_XOR_QUAD_CurrentVersionRun_8a0c {
  strings:
    $key_8a0c = { d9 63 [2] fd 6d [2] d6 41 [2] f8 63 [2] ec 78 [2] e3 62 [2] fd 7f [2] ff 7e [2] e4 78 [2] f8 7f [2] e4 50 }

  condition:
    any of them
}