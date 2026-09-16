rule TTP_XOR_QUAD_CurrentVersionRun_8f02 {
  strings:
    $key_8f02 = { dc 6d [2] f8 63 [2] d3 4f [2] fd 6d [2] e9 76 [2] e6 6c [2] f8 71 [2] fa 70 [2] e1 76 [2] fd 71 [2] e1 5e }

  condition:
    any of them
}