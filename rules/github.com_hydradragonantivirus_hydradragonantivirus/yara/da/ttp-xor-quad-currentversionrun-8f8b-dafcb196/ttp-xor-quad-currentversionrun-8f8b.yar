rule TTP_XOR_QUAD_CurrentVersionRun_8f8b {
  strings:
    $key_8f8b = { dc e4 [2] f8 ea [2] d3 c6 [2] fd e4 [2] e9 ff [2] e6 e5 [2] f8 f8 [2] fa f9 [2] e1 ff [2] fd f8 [2] e1 d7 }

  condition:
    any of them
}