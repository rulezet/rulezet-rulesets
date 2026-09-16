rule TTP_XOR_QUAD_CurrentVersionRun_8f5d {
  strings:
    $key_8f5d = { dc 32 [2] f8 3c [2] d3 10 [2] fd 32 [2] e9 29 [2] e6 33 [2] f8 2e [2] fa 2f [2] e1 29 [2] fd 2e [2] e1 01 }

  condition:
    any of them
}