rule TTP_XOR_QUAD_CurrentVersionRun_8a09 {
  strings:
    $key_8a09 = { d9 66 [2] fd 68 [2] d6 44 [2] f8 66 [2] ec 7d [2] e3 67 [2] fd 7a [2] ff 7b [2] e4 7d [2] f8 7a [2] e4 55 }

  condition:
    any of them
}