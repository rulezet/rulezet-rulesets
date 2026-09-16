rule TTP_XOR_QUAD_CurrentVersionRun_8ae8 {
  strings:
    $key_8ae8 = { d9 87 [2] fd 89 [2] d6 a5 [2] f8 87 [2] ec 9c [2] e3 86 [2] fd 9b [2] ff 9a [2] e4 9c [2] f8 9b [2] e4 b4 }

  condition:
    any of them
}