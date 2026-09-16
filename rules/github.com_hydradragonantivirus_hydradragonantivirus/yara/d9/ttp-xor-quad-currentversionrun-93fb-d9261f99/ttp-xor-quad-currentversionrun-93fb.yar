rule TTP_XOR_QUAD_CurrentVersionRun_93fb {
  strings:
    $key_93fb = { c0 94 [2] e4 9a [2] cf b6 [2] e1 94 [2] f5 8f [2] fa 95 [2] e4 88 [2] e6 89 [2] fd 8f [2] e1 88 [2] fd a7 }

  condition:
    any of them
}