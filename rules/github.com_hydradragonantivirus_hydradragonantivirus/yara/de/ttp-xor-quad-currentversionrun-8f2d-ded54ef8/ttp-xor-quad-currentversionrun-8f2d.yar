rule TTP_XOR_QUAD_CurrentVersionRun_8f2d {
  strings:
    $key_8f2d = { dc 42 [2] f8 4c [2] d3 60 [2] fd 42 [2] e9 59 [2] e6 43 [2] f8 5e [2] fa 5f [2] e1 59 [2] fd 5e [2] e1 71 }

  condition:
    any of them
}