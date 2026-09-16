rule TTP_XOR_QUAD_CurrentVersionRun_8ff5 {
  strings:
    $key_8ff5 = { dc 9a [2] f8 94 [2] d3 b8 [2] fd 9a [2] e9 81 [2] e6 9b [2] f8 86 [2] fa 87 [2] e1 81 [2] fd 86 [2] e1 a9 }

  condition:
    any of them
}