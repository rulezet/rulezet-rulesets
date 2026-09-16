rule TTP_XOR_QUAD_CurrentVersionRun_8f58 {
  strings:
    $key_8f58 = { dc 37 [2] f8 39 [2] d3 15 [2] fd 37 [2] e9 2c [2] e6 36 [2] f8 2b [2] fa 2a [2] e1 2c [2] fd 2b [2] e1 04 }

  condition:
    any of them
}