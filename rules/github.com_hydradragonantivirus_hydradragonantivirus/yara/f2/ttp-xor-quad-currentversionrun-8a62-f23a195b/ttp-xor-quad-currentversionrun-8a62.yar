rule TTP_XOR_QUAD_CurrentVersionRun_8a62 {
  strings:
    $key_8a62 = { d9 0d [2] fd 03 [2] d6 2f [2] f8 0d [2] ec 16 [2] e3 0c [2] fd 11 [2] ff 10 [2] e4 16 [2] f8 11 [2] e4 3e }

  condition:
    any of them
}