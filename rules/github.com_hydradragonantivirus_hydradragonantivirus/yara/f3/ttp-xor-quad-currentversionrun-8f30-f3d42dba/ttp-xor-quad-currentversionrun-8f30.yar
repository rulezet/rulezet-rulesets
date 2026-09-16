rule TTP_XOR_QUAD_CurrentVersionRun_8f30 {
  strings:
    $key_8f30 = { dc 5f [2] f8 51 [2] d3 7d [2] fd 5f [2] e9 44 [2] e6 5e [2] f8 43 [2] fa 42 [2] e1 44 [2] fd 43 [2] e1 6c }

  condition:
    any of them
}