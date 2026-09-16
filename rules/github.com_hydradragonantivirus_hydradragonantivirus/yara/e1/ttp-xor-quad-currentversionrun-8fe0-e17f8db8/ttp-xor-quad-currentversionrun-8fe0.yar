rule TTP_XOR_QUAD_CurrentVersionRun_8fe0 {
  strings:
    $key_8fe0 = { dc 8f [2] f8 81 [2] d3 ad [2] fd 8f [2] e9 94 [2] e6 8e [2] f8 93 [2] fa 92 [2] e1 94 [2] fd 93 [2] e1 bc }

  condition:
    any of them
}