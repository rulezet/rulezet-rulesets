rule TTP_XOR_QUAD_CurrentVersionRun_945d {
  strings:
    $key_945d = { c7 32 [2] e3 3c [2] c8 10 [2] e6 32 [2] f2 29 [2] fd 33 [2] e3 2e [2] e1 2f [2] fa 29 [2] e6 2e [2] fa 01 }

  condition:
    any of them
}