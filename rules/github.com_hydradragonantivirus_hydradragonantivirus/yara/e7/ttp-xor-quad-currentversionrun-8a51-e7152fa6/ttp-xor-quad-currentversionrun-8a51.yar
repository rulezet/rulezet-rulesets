rule TTP_XOR_QUAD_CurrentVersionRun_8a51 {
  strings:
    $key_8a51 = { d9 3e [2] fd 30 [2] d6 1c [2] f8 3e [2] ec 25 [2] e3 3f [2] fd 22 [2] ff 23 [2] e4 25 [2] f8 22 [2] e4 0d }

  condition:
    any of them
}