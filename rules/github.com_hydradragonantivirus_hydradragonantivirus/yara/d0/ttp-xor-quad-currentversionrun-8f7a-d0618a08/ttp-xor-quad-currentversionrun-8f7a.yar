rule TTP_XOR_QUAD_CurrentVersionRun_8f7a {
  strings:
    $key_8f7a = { dc 15 [2] f8 1b [2] d3 37 [2] fd 15 [2] e9 0e [2] e6 14 [2] f8 09 [2] fa 08 [2] e1 0e [2] fd 09 [2] e1 26 }

  condition:
    any of them
}