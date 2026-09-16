rule TTP_XOR_QUAD_CurrentVersionRun_8aef {
  strings:
    $key_8aef = { d9 80 [2] fd 8e [2] d6 a2 [2] f8 80 [2] ec 9b [2] e3 81 [2] fd 9c [2] ff 9d [2] e4 9b [2] f8 9c [2] e4 b3 }

  condition:
    any of them
}