rule TTP_XOR_QUAD_CurrentVersionRun_8f23 {
  strings:
    $key_8f23 = { dc 4c [2] f8 42 [2] d3 6e [2] fd 4c [2] e9 57 [2] e6 4d [2] f8 50 [2] fa 51 [2] e1 57 [2] fd 50 [2] e1 7f }

  condition:
    any of them
}