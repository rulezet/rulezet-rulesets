rule TTP_XOR_QUAD_CurrentVersionRun_8f53 {
  strings:
    $key_8f53 = { dc 3c [2] f8 32 [2] d3 1e [2] fd 3c [2] e9 27 [2] e6 3d [2] f8 20 [2] fa 21 [2] e1 27 [2] fd 20 [2] e1 0f }

  condition:
    any of them
}