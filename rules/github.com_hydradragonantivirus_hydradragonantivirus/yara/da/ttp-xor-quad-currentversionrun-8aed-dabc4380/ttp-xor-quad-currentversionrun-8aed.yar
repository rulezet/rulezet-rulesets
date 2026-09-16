rule TTP_XOR_QUAD_CurrentVersionRun_8aed {
  strings:
    $key_8aed = { d9 82 [2] fd 8c [2] d6 a0 [2] f8 82 [2] ec 99 [2] e3 83 [2] fd 9e [2] ff 9f [2] e4 99 [2] f8 9e [2] e4 b1 }

  condition:
    any of them
}