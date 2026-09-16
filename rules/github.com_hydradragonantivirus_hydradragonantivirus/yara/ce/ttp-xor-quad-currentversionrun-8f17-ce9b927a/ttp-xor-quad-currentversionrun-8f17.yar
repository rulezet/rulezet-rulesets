rule TTP_XOR_QUAD_CurrentVersionRun_8f17 {
  strings:
    $key_8f17 = { dc 78 [2] f8 76 [2] d3 5a [2] fd 78 [2] e9 63 [2] e6 79 [2] f8 64 [2] fa 65 [2] e1 63 [2] fd 64 [2] e1 4b }

  condition:
    any of them
}