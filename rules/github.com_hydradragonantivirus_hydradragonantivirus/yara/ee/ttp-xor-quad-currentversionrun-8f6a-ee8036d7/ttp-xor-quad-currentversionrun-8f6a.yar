rule TTP_XOR_QUAD_CurrentVersionRun_8f6a {
  strings:
    $key_8f6a = { dc 05 [2] f8 0b [2] d3 27 [2] fd 05 [2] e9 1e [2] e6 04 [2] f8 19 [2] fa 18 [2] e1 1e [2] fd 19 [2] e1 36 }

  condition:
    any of them
}