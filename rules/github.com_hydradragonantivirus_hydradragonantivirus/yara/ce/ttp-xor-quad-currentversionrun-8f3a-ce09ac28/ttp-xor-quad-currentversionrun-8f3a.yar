rule TTP_XOR_QUAD_CurrentVersionRun_8f3a {
  strings:
    $key_8f3a = { dc 55 [2] f8 5b [2] d3 77 [2] fd 55 [2] e9 4e [2] e6 54 [2] f8 49 [2] fa 48 [2] e1 4e [2] fd 49 [2] e1 66 }

  condition:
    any of them
}