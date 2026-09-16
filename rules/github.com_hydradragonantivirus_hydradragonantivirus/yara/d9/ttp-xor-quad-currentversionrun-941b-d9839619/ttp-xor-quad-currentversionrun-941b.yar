rule TTP_XOR_QUAD_CurrentVersionRun_941b {
  strings:
    $key_941b = { c7 74 [2] e3 7a [2] c8 56 [2] e6 74 [2] f2 6f [2] fd 75 [2] e3 68 [2] e1 69 [2] fa 6f [2] e6 68 [2] fa 47 }

  condition:
    any of them
}