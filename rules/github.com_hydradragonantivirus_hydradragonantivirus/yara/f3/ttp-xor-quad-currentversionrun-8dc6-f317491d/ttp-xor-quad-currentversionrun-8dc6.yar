rule TTP_XOR_QUAD_CurrentVersionRun_8dc6 {
  strings:
    $key_8dc6 = { de a9 [2] fa a7 [2] d1 8b [2] ff a9 [2] eb b2 [2] e4 a8 [2] fa b5 [2] f8 b4 [2] e3 b2 [2] ff b5 [2] e3 9a }

  condition:
    any of them
}