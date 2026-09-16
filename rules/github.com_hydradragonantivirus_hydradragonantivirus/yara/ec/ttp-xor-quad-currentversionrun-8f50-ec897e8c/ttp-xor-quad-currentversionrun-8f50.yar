rule TTP_XOR_QUAD_CurrentVersionRun_8f50 {
  strings:
    $key_8f50 = { dc 3f [2] f8 31 [2] d3 1d [2] fd 3f [2] e9 24 [2] e6 3e [2] f8 23 [2] fa 22 [2] e1 24 [2] fd 23 [2] e1 0c }

  condition:
    any of them
}