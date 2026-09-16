rule TTP_XOR_QUAD_CurrentVersionRun_8dc0 {
  strings:
    $key_8dc0 = { de af [2] fa a1 [2] d1 8d [2] ff af [2] eb b4 [2] e4 ae [2] fa b3 [2] f8 b2 [2] e3 b4 [2] ff b3 [2] e3 9c }

  condition:
    any of them
}