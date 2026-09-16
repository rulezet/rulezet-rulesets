rule TTP_XOR_QUAD_CurrentVersionRun_8f0b {
  strings:
    $key_8f0b = { dc 64 [2] f8 6a [2] d3 46 [2] fd 64 [2] e9 7f [2] e6 65 [2] f8 78 [2] fa 79 [2] e1 7f [2] fd 78 [2] e1 57 }

  condition:
    any of them
}