rule TTP_XOR_QUAD_CurrentVersionRun_8f26 {
  strings:
    $key_8f26 = { dc 49 [2] f8 47 [2] d3 6b [2] fd 49 [2] e9 52 [2] e6 48 [2] f8 55 [2] fa 54 [2] e1 52 [2] fd 55 [2] e1 7a }

  condition:
    any of them
}