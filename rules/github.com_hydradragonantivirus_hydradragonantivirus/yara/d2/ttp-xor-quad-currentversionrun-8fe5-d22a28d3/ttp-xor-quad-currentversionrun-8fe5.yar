rule TTP_XOR_QUAD_CurrentVersionRun_8fe5 {
  strings:
    $key_8fe5 = { dc 8a [2] f8 84 [2] d3 a8 [2] fd 8a [2] e9 91 [2] e6 8b [2] f8 96 [2] fa 97 [2] e1 91 [2] fd 96 [2] e1 b9 }

  condition:
    any of them
}