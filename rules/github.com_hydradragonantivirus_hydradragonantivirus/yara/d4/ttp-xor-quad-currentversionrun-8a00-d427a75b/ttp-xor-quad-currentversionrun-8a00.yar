rule TTP_XOR_QUAD_CurrentVersionRun_8a00 {
  strings:
    $key_8a00 = { d9 6f [2] fd 61 [2] d6 4d [2] f8 6f [2] ec 74 [2] e3 6e [2] fd 73 [2] ff 72 [2] e4 74 [2] f8 73 [2] e4 5c }

  condition:
    any of them
}