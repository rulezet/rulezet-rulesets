rule TTP_XOR_QUAD_CurrentVersionRun_8f45 {
  strings:
    $key_8f45 = { dc 2a [2] f8 24 [2] d3 08 [2] fd 2a [2] e9 31 [2] e6 2b [2] f8 36 [2] fa 37 [2] e1 31 [2] fd 36 [2] e1 19 }

  condition:
    any of them
}