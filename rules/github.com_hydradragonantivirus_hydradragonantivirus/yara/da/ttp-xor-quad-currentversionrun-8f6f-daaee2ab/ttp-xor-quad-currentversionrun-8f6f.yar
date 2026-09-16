rule TTP_XOR_QUAD_CurrentVersionRun_8f6f {
  strings:
    $key_8f6f = { dc 00 [2] f8 0e [2] d3 22 [2] fd 00 [2] e9 1b [2] e6 01 [2] f8 1c [2] fa 1d [2] e1 1b [2] fd 1c [2] e1 33 }

  condition:
    any of them
}