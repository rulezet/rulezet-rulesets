rule TTP_XOR_QUAD_CurrentVersionRun_8ff7 {
  strings:
    $key_8ff7 = { dc 98 [2] f8 96 [2] d3 ba [2] fd 98 [2] e9 83 [2] e6 99 [2] f8 84 [2] fa 85 [2] e1 83 [2] fd 84 [2] e1 ab }

  condition:
    any of them
}