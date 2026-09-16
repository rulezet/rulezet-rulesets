rule TTP_XOR_QUAD_CurrentVersionRun_8ff4 {
  strings:
    $key_8ff4 = { dc 9b [2] f8 95 [2] d3 b9 [2] fd 9b [2] e9 80 [2] e6 9a [2] f8 87 [2] fa 86 [2] e1 80 [2] fd 87 [2] e1 a8 }

  condition:
    any of them
}