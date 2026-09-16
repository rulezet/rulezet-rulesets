rule TTP_XOR_QUAD_CurrentVersionRun_8f55 {
  strings:
    $key_8f55 = { dc 3a [2] f8 34 [2] d3 18 [2] fd 3a [2] e9 21 [2] e6 3b [2] f8 26 [2] fa 27 [2] e1 21 [2] fd 26 [2] e1 09 }

  condition:
    any of them
}