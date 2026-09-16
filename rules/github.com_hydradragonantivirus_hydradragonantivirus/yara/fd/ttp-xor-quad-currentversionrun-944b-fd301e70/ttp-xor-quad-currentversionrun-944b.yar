rule TTP_XOR_QUAD_CurrentVersionRun_944b {
  strings:
    $key_944b = { c7 24 [2] e3 2a [2] c8 06 [2] e6 24 [2] f2 3f [2] fd 25 [2] e3 38 [2] e1 39 [2] fa 3f [2] e6 38 [2] fa 17 }

  condition:
    any of them
}