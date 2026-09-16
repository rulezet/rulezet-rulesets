rule TTP_XOR_QUAD_CurrentVersionRun_8f1b {
  strings:
    $key_8f1b = { dc 74 [2] f8 7a [2] d3 56 [2] fd 74 [2] e9 6f [2] e6 75 [2] f8 68 [2] fa 69 [2] e1 6f [2] fd 68 [2] e1 47 }

  condition:
    any of them
}