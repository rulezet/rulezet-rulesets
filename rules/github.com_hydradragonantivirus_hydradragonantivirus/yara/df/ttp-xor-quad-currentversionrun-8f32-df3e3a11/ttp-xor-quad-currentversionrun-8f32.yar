rule TTP_XOR_QUAD_CurrentVersionRun_8f32 {
  strings:
    $key_8f32 = { dc 5d [2] f8 53 [2] d3 7f [2] fd 5d [2] e9 46 [2] e6 5c [2] f8 41 [2] fa 40 [2] e1 46 [2] fd 41 [2] e1 6e }

  condition:
    any of them
}