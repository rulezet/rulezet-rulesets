rule TTP_XOR_QUAD_CurrentVersionRun_8f00 {
  strings:
    $key_8f00 = { dc 6f [2] f8 61 [2] d3 4d [2] fd 6f [2] e9 74 [2] e6 6e [2] f8 73 [2] fa 72 [2] e1 74 [2] fd 73 [2] e1 5c }

  condition:
    any of them
}