rule TTP_XOR_QUAD_CurrentVersionRun_8f25 {
  strings:
    $key_8f25 = { dc 4a [2] f8 44 [2] d3 68 [2] fd 4a [2] e9 51 [2] e6 4b [2] f8 56 [2] fa 57 [2] e1 51 [2] fd 56 [2] e1 79 }

  condition:
    any of them
}