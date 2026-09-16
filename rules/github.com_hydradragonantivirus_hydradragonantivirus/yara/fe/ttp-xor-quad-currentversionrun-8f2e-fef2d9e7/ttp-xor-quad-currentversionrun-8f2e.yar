rule TTP_XOR_QUAD_CurrentVersionRun_8f2e {
  strings:
    $key_8f2e = { dc 41 [2] f8 4f [2] d3 63 [2] fd 41 [2] e9 5a [2] e6 40 [2] f8 5d [2] fa 5c [2] e1 5a [2] fd 5d [2] e1 72 }

  condition:
    any of them
}