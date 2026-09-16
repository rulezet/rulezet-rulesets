rule TTP_XOR_QUAD_CurrentVersionRun_8f14 {
  strings:
    $key_8f14 = { dc 7b [2] f8 75 [2] d3 59 [2] fd 7b [2] e9 60 [2] e6 7a [2] f8 67 [2] fa 66 [2] e1 60 [2] fd 67 [2] e1 48 }

  condition:
    any of them
}