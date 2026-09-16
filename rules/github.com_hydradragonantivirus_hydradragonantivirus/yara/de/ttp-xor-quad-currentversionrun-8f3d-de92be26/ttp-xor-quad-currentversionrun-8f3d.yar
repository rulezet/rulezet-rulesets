rule TTP_XOR_QUAD_CurrentVersionRun_8f3d {
  strings:
    $key_8f3d = { dc 52 [2] f8 5c [2] d3 70 [2] fd 52 [2] e9 49 [2] e6 53 [2] f8 4e [2] fa 4f [2] e1 49 [2] fd 4e [2] e1 61 }

  condition:
    any of them
}