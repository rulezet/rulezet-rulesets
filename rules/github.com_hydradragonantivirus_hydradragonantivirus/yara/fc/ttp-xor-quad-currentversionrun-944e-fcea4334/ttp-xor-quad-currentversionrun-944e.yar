rule TTP_XOR_QUAD_CurrentVersionRun_944e {
  strings:
    $key_944e = { c7 21 [2] e3 2f [2] c8 03 [2] e6 21 [2] f2 3a [2] fd 20 [2] e3 3d [2] e1 3c [2] fa 3a [2] e6 3d [2] fa 12 }

  condition:
    any of them
}