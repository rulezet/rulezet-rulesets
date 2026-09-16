rule TTP_XOR_QUAD_CurrentVersionRun_8f4a {
  strings:
    $key_8f4a = { dc 25 [2] f8 2b [2] d3 07 [2] fd 25 [2] e9 3e [2] e6 24 [2] f8 39 [2] fa 38 [2] e1 3e [2] fd 39 [2] e1 16 }

  condition:
    any of them
}