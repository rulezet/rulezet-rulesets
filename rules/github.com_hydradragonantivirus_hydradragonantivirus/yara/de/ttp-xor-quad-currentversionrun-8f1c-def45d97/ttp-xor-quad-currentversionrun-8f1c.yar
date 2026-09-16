rule TTP_XOR_QUAD_CurrentVersionRun_8f1c {
  strings:
    $key_8f1c = { dc 73 [2] f8 7d [2] d3 51 [2] fd 73 [2] e9 68 [2] e6 72 [2] f8 6f [2] fa 6e [2] e1 68 [2] fd 6f [2] e1 40 }

  condition:
    any of them
}