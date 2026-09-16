rule TTP_XOR_QUAD_CurrentVersionRun_8f29 {
  strings:
    $key_8f29 = { dc 46 [2] f8 48 [2] d3 64 [2] fd 46 [2] e9 5d [2] e6 47 [2] f8 5a [2] fa 5b [2] e1 5d [2] fd 5a [2] e1 75 }

  condition:
    any of them
}