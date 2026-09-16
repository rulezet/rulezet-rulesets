rule TTP_XOR_QUAD_CurrentVersionRun_9440 {
  strings:
    $key_9440 = { c7 2f [2] e3 21 [2] c8 0d [2] e6 2f [2] f2 34 [2] fd 2e [2] e3 33 [2] e1 32 [2] fa 34 [2] e6 33 [2] fa 1c }

  condition:
    any of them
}