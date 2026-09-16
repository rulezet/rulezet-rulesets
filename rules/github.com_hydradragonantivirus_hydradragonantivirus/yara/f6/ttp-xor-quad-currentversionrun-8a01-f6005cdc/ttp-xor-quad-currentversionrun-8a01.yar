rule TTP_XOR_QUAD_CurrentVersionRun_8a01 {
  strings:
    $key_8a01 = { d9 6e [2] fd 60 [2] d6 4c [2] f8 6e [2] ec 75 [2] e3 6f [2] fd 72 [2] ff 73 [2] e4 75 [2] f8 72 [2] e4 5d }

  condition:
    any of them
}