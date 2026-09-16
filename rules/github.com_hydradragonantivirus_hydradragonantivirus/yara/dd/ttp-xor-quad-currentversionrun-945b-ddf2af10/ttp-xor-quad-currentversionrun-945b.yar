rule TTP_XOR_QUAD_CurrentVersionRun_945b {
  strings:
    $key_945b = { c7 34 [2] e3 3a [2] c8 16 [2] e6 34 [2] f2 2f [2] fd 35 [2] e3 28 [2] e1 29 [2] fa 2f [2] e6 28 [2] fa 07 }

  condition:
    any of them
}