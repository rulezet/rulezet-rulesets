rule TTP_XOR_QUAD_CurrentVersionRun_8dc7 {
  strings:
    $key_8dc7 = { de a8 [2] fa a6 [2] d1 8a [2] ff a8 [2] eb b3 [2] e4 a9 [2] fa b4 [2] f8 b5 [2] e3 b3 [2] ff b4 [2] e3 9b }

  condition:
    any of them
}